"""
Control-flow unflattening analysis using symbolic execution and CFG reasoning.

This module analyzes control flow flattened functions and reconstructs the
mapping between dispatcher states and original basic-block entry points.
It utilises symbolic execution and patterns in assembly, to recover state transitions.

Core responsibilities:
    - Identify whether a function is control flow flattened
    - Detect the dispatcher basic block
    - Identify the state register used by the dispatcher
    - Recover all transitions into the dispatcher (state assignments)
    - Recover all transitions out of the dispatcher (state resolution)
    - Produce a StateToNodeMapping suitable for binary rewriting

Dispatcher interaction categories:
    - Dispatcher entrances:
        Unconditional jumps into the dispatcher preceded by immediate
        assignments to the state register.

    - Conditional dispatcher jumps:
        Unconditional jumps into the dispatcher where the state register
        is conditionally assigned one of multiple values (via cmovcc or
        arithmetic flag-based instruction sequences).

    - Unflattened conditionals:
        Conditional jumps where only one branch re-enters the dispatcher
        and the other case continues execution of original code.

    - Dispatcher exits:
        Jumps leaving the dispatcher into original basic blocks after
        the state value has been resolved.

Its output is consumed by the rewriting module which reconstructs
structured control flow in a new binary section.
"""

import collections
import logging

import angr
import angrmanagement
from angrmanagement.utils.graph import to_supergraph
from angr.utils.graph import Dominators
import claripy
from capstone import *
from capstone.x86 import *
import networkx

from graphs import StateToNodeMapping

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)


class FunctionNotFlattened(Exception):
    pass


class AnalyzerContext:
    """
    Top-level analysis coordinator for control-flow unflattening.

    This class owns the angr Project and the global CFGs. It is responsible
    for building heavyweight analysis artifacts exactly once and providing
    per-function analysis contexts via Analyzer instances.

    Responsibilities:
        - Load the binary into angr
        - Build the master CFG (normal and normalized)
        - Dispatch per-function unflattening analysis

    The Unflatten object itself is stateless with respect to individual
    functions; all per-function state is contained in Analyzer.
    """

    def __init__(self, fpath: str):
        self.proj = angr.Project(fpath, auto_load_libs=False)
        self.bitness = self.proj.arch.bits
        if self.bitness != 32 and self.bitness != 64:
            raise TypeError
        self.master_cfg = self.proj.analyses.CFGFast()
        self.normalised_master_cfg = self.proj.analyses.CFGFast(normalize=True)

    def analyse(self, func_addr):
        """
        Return a per-function analysis object.
        """
        return FunctionAnalyzer(self, func_addr)


class FunctionAnalyzer:
    """
    Per-function control-flow unflattening analysis.

    This class performs all analysis necessary to recover the control-flow
    structure of a single flattened function. It identifies the dispatcher,
    determines the state register, explores all dispatcher interactions,
    and builds a StateToNodeMapping describing the recovered CFG structure.

    Key analysis steps:
        - Verify that the function is flattened
        - Identify the dispatcher block
        - Identify the state register
        - Compute the dispatcher chain (dispatcher + glue blocks)
        - Recover all dispatcher entrances, exits, and conditional transitions
        - Resolve state values via symbolic execution where necessary

    Output:
        - A fully populated StateToNodeMapping instance suitable for
          control-flow reconstruction and binary rewriting.
    """

    def __init__(self, parent, func_addr):
        self._dominator_tree = None
        self.func_addr = func_addr
        self.proj: angr.project.Project = parent.proj
        self.parent = parent
        self.func_cfg: angr.knowledge_plugins.functions.function.Function = (
            parent.master_cfg.kb.functions[func_addr]
        )
        self.master_cfg = parent.master_cfg
        self.transition_graph: networkx.classes.digraph.DiGraph = (
            self.func_cfg.transition_graph
        )

        if not self.is_flattened():
            raise FunctionNotFlattened(f"{hex(func_addr)} is not flattened")

        self.supergraph = to_supergraph(self.func_cfg.transition_graph)
        self.dispatcher: angrmanagement.utils.graph.SuperCFGNode = self.get_dispatcher()
        self.dispatcher_range = []
        dnode = self._get_node(self.dispatcher.addr)
        for addr in range(self.dispatcher.addr, dnode.instruction_addrs[-1]):
            self.dispatcher_range.append(addr)
        self.state_reg: str = self.get_state_reg()
        self.dispatcher_chain = self.get_dispatcher_chain()
        self._state_value = None
        self.state_to_node_mapping = StateToNodeMapping()
        self.dispatcher_range = []

        if parent.bitness == 64:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        elif parent.bitness == 32:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True

        self._length_limit = None

    @property
    def dominator_tree(self):
        if self._dominator_tree is None:
            entry = self._get_tg_node(self.func_addr)
            idom = Dominators(self.func_cfg.graph, entry)
            idom.dom.remove_node(entry)

            self._dominator_tree = idom.dom
        return self._dominator_tree

    @property
    def length_limit(self):
        if self._length_limit is None:
            self._length_limit = (
                len(self.get_dispatcher_successors())
                * len(self.func_cfg.block_addrs_set)
                // 2
            )
        return self._length_limit

    def is_flattened(
        self, dominance_threshold: float = 0.8, min_back_edges: int = 2
    ) -> bool:
        """
        Determine whether the function is control-flow flattened.

        Uses the same dominance + back-edge logic as get_dispatcher(),
        but returns a boolean instead of a dispatcher node.

        Args:
            dominance_threshold (float):
                Fraction of CFG nodes a block must dominate to be suspicious.
            min_back_edges (int):
                Minimum number of back edges required.
                Usually 2 is enough for detection.

        Returns:
            bool: True if the function appears flattened, False otherwise.
        """

        dominance_score = dict()

        for n in self.dominator_tree.nodes:
            dominated = networkx.descendants(self.dominator_tree, n) | {n}
            dominance_score[n] = len(dominated)

        total_nodes = len(self.dominator_tree.nodes)
        if total_nodes < 3:
            return False

        back_edge_count = {n: 0 for n in self.dominator_tree.nodes}
        entry = self._get_tg_node(self.func_addr)

        for src, dst in self.transition_graph.edges():
            if src is entry:
                continue

            if dst in networkx.ancestors(self.dominator_tree, src):
                back_edge_count[dst] += 1

        for n in self.dominator_tree.nodes:
            domination_ratio = dominance_score[n] / total_nodes

            if (
                domination_ratio >= dominance_threshold
                and back_edge_count[n] >= min_back_edges
                and n is not entry
            ):
                return True

        return False

    def get_dispatcher(self) -> angr.codenode.BlockNode:
        """
        Determine the dispatcher by scanning the normal angr CFG (not the supergraph)
        and selecting the basic block with the most predecessors.

        Dispatcher = block with the highest number of incoming edges.
        """
        dominance_score = dict()
        for n in self.dominator_tree.nodes:
            if not hasattr(n, "addr"):
                continue
            dominated = networkx.descendants(self.dominator_tree, n) | {n}
            dominance_score[n] = len(dominated)
        back_edge_count = {
            n: 0 for n in self.transition_graph.nodes if n in self.dominator_tree.nodes
        }
        entry = self._get_tg_node(self.func_addr)
        for src, dst in self.transition_graph.edges():
            if src is entry:
                continue
            if dst in networkx.ancestors(self.dominator_tree, src):
                back_edge_count[dst] += 1

        candidates = sorted(
            self.dominator_tree.nodes,
            key=lambda n: (dominance_score.get(n, 0), back_edge_count.get(n, 0)),
            reverse=True,
        )
        dispatcher_ = None
        for c in candidates:
            if back_edge_count[c] > 0:
                dispatcher_ = c
                break

        dispatcher_ = self.merge_calls(self._get_node(dispatcher_.addr))
        return dispatcher_

    def get_dispatcher_start(self):
        ip = self.dispatcher.instruction_addrs[-2]
        return ip

    def get_dispatcher_end(self):
        ip = self.dispatcher.instruction_addrs[-1]
        return ip

    def extract_state_reg_hook(self, state) -> claripy.BVS:
        self._state_value = getattr(state.regs, self.state_reg)
        state.globals["stop_now"] = True

    def create_blank_state(
        self, ip: int, zero_fill_mem=False, calless=True, lazy_solves=False
    ):
        s = self.proj.factory.call_state(ip)
        s.options.add(angr.options.CALLLESS)
        if zero_fill_mem:
            s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        if lazy_solves:
            s.options.add(angr.options.LAZY_SOLVES)

        return s

    def make_simgr(
        self, state, limit_length=False, time_out=30, threading=False, dfs=False
    ):
        simgr = self.proj.factory.simulation_manager(state)
        timeout = len(self.func_cfg.block_addrs) * 2
        simgr.use_technique(angr.exploration_techniques.timeout.Timeout(timeout))
        return simgr

    def get_start_addr(self):
        """
        Not sure why but using the function start results in Angr not working. So grabbing second instruciton in the function as the start address
        """
        block = self.proj.factory.block(self.func_addr)
        insn = block.capstone.insns[0]
        addr = insn.address + insn.size
        return addr

    def get_dispatcher_chain(self):
        """
        gets nodes that are a part of the dispatcher chain
        """
        disp_chain = self.get_glue_blocks()
        dnode = self._get_node(self.dispatcher.addr)
        for addr in range(self.dispatcher.addr, dnode.instruction_addrs[-1]):
            disp_chain.add(addr)
        return disp_chain

    def get_branching_nodes(self) -> dict[int : list[int]]:
        """
        gets nodes that have multiple outgoing edges
        """
        branching_supernodes = dict()
        for n in self.func_cfg.graph.nodes():

            succs = list(self.func_cfg.graph.successors(n))
            if len(succs) > 1:
                branching_supernodes[n.addr] = [succ.addr for succ in succs]

        return branching_supernodes

    def get_glue_blocks(self) -> set[int]:
        """
        Scan the CFG basic block graph for glue blocks.

        A glue block is defined as a block containing:
        - cmp state_reg, imm
        - jz or jnz

        Returns:
            Set of block addresses.
        """

        glue_blocks = set()
        for node in self.func_cfg.nodes:
            if self.func_addr > node.addr or node.addr > (
                self.func_addr + self.func_cfg.size
            ):
                continue
            node = self._get_node(node.addr)
            insns = [i for i in node.block.disassembly.insns if i.mnemonic != "nop"]
            if len(insns) != 2:
                continue
            cmp_insn, jmp_insn = insns
            if cmp_insn.mnemonic != "cmp":
                continue
            ops = cmp_insn.operands
            if len(ops) != 2:
                continue
            reg_name = cmp_insn.reg_name(ops[0].reg)
            if reg_name != self.state_reg:
                continue
            if jmp_insn.mnemonic not in ("jz", "jnz", "je", "jne", "jg"):
                continue
            glue_blocks.add(node.addr)
        for node in self.func_cfg.nodes:
            if self.func_addr > node.addr or node.addr >= (
                self.func_addr + self.func_cfg.size
            ):
                continue
            node = self._get_node(node.addr)
            node = self.get_initial_node_before_calls(node)
            insns = [i for i in node.block.disassembly.insns if i.mnemonic != "nop"]
            if len(insns) != 1:
                continue
            insn = insns[0]
            if insn.mnemonic in ("jz", "je"):
                if insn.operands and insn.operands[0].type == X86_OP_IMM:
                    targets = []
                    targets.append(insn.address + insn.size)
                    targets.append(insn.operands[0].imm)
                    for target in targets:
                        if target in self.dispatcher_range or target in glue_blocks:
                            glue_blocks.add(node.addr)
            if insn.mnemonic == "jmp":
                if insn.operands and insn.operands[0].type == X86_OP_IMM:
                    target = insn.operands[0].imm
                    if target in self.dispatcher_range or target in glue_blocks:
                        glue_blocks.add(node.addr)

        return glue_blocks

    def get_unflat_conditionals(self) -> list[int]:
        """
        Unflat conditionals are considered as nodes in which one of the successors goes to dispatcher chain, other one goes to original basic block
        returns the address of the jcc instruction
        """
        disp_chain = self.dispatcher_chain
        branching_supernodes = self.get_branching_nodes()
        unflat_conditionals = set()
        for n, succs in branching_supernodes.items():
            if (n in disp_chain) or (all(succ in disp_chain for succ in succs)):
                continue
            if any(succ in disp_chain for succ in succs):
                # one of the nodes successors goes to dispatcher chain, other one goes to original basic block
                cond_jmp_addr = self._get_node(n).instruction_addrs[-1]
                raw = bytes(self.proj.loader.memory.load(cond_jmp_addr, 10))
                insn = list(self.cs.disasm(raw, cond_jmp_addr))[0]
                assert insn.operands[0].type == X86_OP_IMM
                target = insn.operands[0].imm
                if target not in disp_chain:
                    dispatcher_addr = insn.address + insn.size
                    cond_jmp_addr = self.linear_walk_until_dispatcher(dispatcher_addr)

                unflat_conditionals.add(cond_jmp_addr)
        return unflat_conditionals

    def explore_unflattened_conditionals(self):

        ip = self.get_start_addr()
        unflat_conditionals = self.get_unflat_conditionals()
        if not unflat_conditionals:
            return None

        for cn in unflat_conditionals:

            found_states = []
            state = [self.create_blank_state(ip)]
            simgr = self.make_simgr(state, limit_length=False)

            simgr.explore(find=cn, n=self.length_limit)

            if simgr.found:
                found_states = list(simgr.found)
            for f in found_states:
                next_state_val_bvs = getattr(f.regs, self.state_reg)
                next_state_value = f.solver.eval_upto(next_state_val_bvs, 10)

                assert len(next_state_value) == 1
                for n in next_state_value:
                    self.state_to_node_mapping.add_unflat_conditional(cn, n)
        mapped_unflat_conds = set()
        for k, v in self.state_to_node_mapping.unflat_conditionals.items():
            mapped_unflat_conds.add(k)
            assert len(v) == 1

        for unflat_conds in unflat_conditionals:
            assert unflat_conds in mapped_unflat_conds

    def get_conditional_nodes(self) -> list[int]:
        """
        Conditional nodes are nodes that contain the instructions:
            sbb state_reg, state_reg
        or
            cmovcc state_reg, state_reg
        Results in multiple possible states when this node enters back into the dispatcher
        """
        conditional_blocks = []
        for b in self.func_cfg.blocks:
            for ins in b.capstone.insns:
                if ins.mnemonic == "sbb":
                    if len(ins.operands) == 2:
                        op0 = ins.reg_name(ins.operands[0].reg)
                        op1 = ins.reg_name(ins.operands[1].reg)  #
                        if op0 == self.state_reg and op1 == self.state_reg:
                            conditional_blocks.append(
                                ins.address
                            )  # if sbb state_reg, state_reg

                if "cmov" in ins.mnemonic:
                    op0 = ins.reg_name(ins.operands[0].reg)
                    if op0 == self.state_reg:
                        conditional_blocks.append(
                            ins.address
                        )  # if cmovz state_reg, any

        if conditional_blocks:
            return conditional_blocks
        return None

    def explore_conditional_nodes(self):
        cnodes = self.get_conditional_nodes()
        if not cnodes:
            return None

        ip = self.get_start_addr()
        state = self.create_blank_state(ip)
        initial_states = [state]
        end_addrs = []

        for n in cnodes:
            end = self.linear_walk_until_dispatcher(n)
            end_addrs.append(end)

            extracted_next_states = set()
            simgr = self.make_simgr(initial_states, limit_length=False)
            prev_found = []
            num_restart = 0
            while True:
                simgr.explore(find=n, n=self.length_limit)
                found = list(simgr.found)
                if found == prev_found:  # no more progess being made
                    simgr = self.make_simgr(
                        initial_states, limit_length=False
                    )  # still using the original state that lead to the dead end, so shouldn't resuing this state lead to the dead end again
                    num_restart += 1  # but it works, not sure why
                    if num_restart > 25:  # prevent infinite loop
                        break
                    else:
                        continue
                prev_found = found

                for state_at_cond in found:
                    next_state_values = self.get_next_state_value(state_at_cond, end)
                    next_states = state_at_cond.solver.eval_upto(next_state_values, 16)

                    if len(next_states) >= 10:
                        continue

                    for next_state in next_states:
                        self.state_to_node_mapping.add_conditional_jump(end, next_state)
                        extracted_next_states.add(next_state)

                if len(extracted_next_states) >= 2:
                    break

        mapped_cond_jumps = set(self.state_to_node_mapping.conditional_jmps.keys())
        for k, v in self.state_to_node_mapping.conditional_jmps.items():
            assert len(v) >= 2

        for cnode_end in end_addrs:
            assert cnode_end in mapped_cond_jumps

    def get_dispatcher_entrances(self):
        """
        Gets any jump addresses into the dispatcher
        """
        dispatcher_entrances = self.get_dispatcher_predecessors()
        entry_addrs = self.merge_calls(self._get_node(self.func_addr)).instruction_addrs
        unflat_conds = list(self.state_to_node_mapping.unflat_conditionals.keys())

        disaptcher_entrances = []
        for i in dispatcher_entrances:
            end = self.linear_walk_until_dispatcher(i)
            if end in unflat_conds or i in entry_addrs:
                continue
            disaptcher_entrances.append((i, end))

        return disaptcher_entrances

    def explore_dispatcher_entrances(self):
        """
        for each unconditional jump/ entrance into the dispatcher, gets the state value when it re-enters the dispatcher
        """
        dispatcher_entrances = self.get_dispatcher_entrances()
        if not dispatcher_entrances:
            return None

        glue_blocks = self.get_glue_blocks()

        ip = self.get_start_addr()

        for n in dispatcher_entrances:
            start, end = n
            start = self._get_tg_node(start)
            paths_to_start = self.find_all_paths_to(start)
            for path in paths_to_start:
                states = []
                inner_state = []
                inner_state.append(self.create_blank_state(ip))
                states.append(inner_state)
                path = path[1:]  # removing first element which is entry node
                path.append(hex(end))
                path.reverse()  # end of the list will now be the first nodes in the path, allowing for pop()
                simgr = None
                while path:
                    addr = path.pop()
                    addr = int(addr, 16)  # hex string to int
                    if addr in glue_blocks:
                        continue
                    if addr < self.get_dispatcher_end():
                        continue
                    new_states = []
                    for state in states:
                        simgr = self.make_simgr(state, limit_length=False, time_out=30)
                        simgr.explore(find=addr, n=self.length_limit)
                        new_states.extend(simgr.found)

                    if not new_states:
                        break  # this path is dead

                    states = new_states  # advance worklist

                for f in new_states:
                    state_value = f.solver.eval_upto(
                        getattr(f.regs, self.state_reg), 16
                    )
                    if len(state_value) > 12:
                        continue
                    for s in state_value:
                        if end in self.state_to_node_mapping.conditional_jmps.keys():
                            self.state_to_node_mapping.add_conditional_jump(
                                end, s
                            )  # sometimes the tail of a conditional node is shared by regular dispatcher entraces as well
                        else:
                            self.state_to_node_mapping.add_dispatcher_entrance(end, s)

        mapped_dispatcher_entrances = set()
        move_to_conditonals = []
        for k, v in self.state_to_node_mapping.dispatcher_entrance.items():
            mapped_dispatcher_entrances.add(k)
            if len(v) > 1:
                # should only be 1 next state possible
                move_to_conditonals.append(k)

        for k in self.state_to_node_mapping.conditional_jmps.keys():
            mapped_dispatcher_entrances.add(k)

        for i in move_to_conditonals:
            self.state_to_node_mapping.move_dispatcher_entrance_to_conditional(i)
        # seems there are dead nodes that don't get mapped, cannot assert all identified entrances get mapped to a state value

    def find_all_paths_to(self, target_node):
        paths = []
        graph = self.func_cfg.graph
        entry = self._get_tg_node(self.func_addr)
        for path in networkx.all_simple_paths(graph, source=entry, target=target_node):
            paths.append([hex(n.addr) for n in path])
        return paths

    def explore_dispatcher_exits(self):
        """
        Gets the state value of all nodes immediately when they exit out of the dispatcher
        """

        dispatcher_exits_dispatcher = self.get_dispatcher_successors()
        state = [self.create_blank_state(self.get_start_addr())]
        for (
            disp_exit,
            dispatcher,
        ) in (
            dispatcher_exits_dispatcher
        ):  # make sure we explore to the node through the its dispatcher predecessor

            simgr = self.make_simgr(state, limit_length=False)
            extracted_state_value = False
            while simgr.active and (
                len(simgr.active) < 1000
            ):  # .explore will stop once one state reaches found. This will get all possible states in found

                if extracted_state_value:
                    break
                simgr.explore(find=disp_exit, n=self.length_limit)
                if len(simgr.found) > 100:
                    break
                found = simgr.found

                if not found:
                    break
                for f in found:
                    prev_bb_addrs = list(
                        self._get_node(f.history.bbl_addrs[-1]).instruction_addrs
                    )  # need all addrs to prevent conflicts with blocks being split on jumps to middle of them

                    if dispatcher not in prev_bb_addrs:
                        continue
                        # making sure we ran to this address directly through the dispatcher
                    state_value = f.solver.eval_upto(getattr(f.regs, self.state_reg), 4)
                    if len(state_value) != 1:
                        continue
                    s = state_value[0]
                    extracted_state_value = True
                    self.state_to_node_mapping.add_dispatcher_exit(disp_exit, s)
                    break
        # Dead code is present/ states that don't get mapped. Cannot assert all identified entrances have been mapped to a state

    def explore_entry_nodes(self):
        dispatcher_end = self.get_node_end(self.dispatcher)
        ip = self.get_start_addr()
        state = self.create_blank_state(ip)
        state_bvs = self.get_next_state_value(state, dispatcher_end)
        state_value = state.solver.eval_upto(state_bvs, 2)
        assert len(state_value) == 1
        state_value = state_value[0]
        disp_start = self.get_dispatcher_end()
        self.state_to_node_mapping.add_dispatcher_entrance(disp_start, state_value)

    def get_dispatcher_successors(self) -> list[tuple[int, int]]:
        """
        returns a list of tuples. Each tuple contains the dispatcher successor address and also the dispatcher node address.
        """
        successors = set()
        glue = self.get_glue_blocks()
        for addr in glue:
            node = self._get_node(addr)
            for succ in node.successors:
                if succ.addr not in self.dispatcher_chain:
                    successors.add((succ.addr, addr))
        return successors

    def get_dispatcher_predecessors(self):
        predecessors = set()
        glue = self.get_glue_blocks()
        glue.add(self.dispatcher.addr)
        for i in range(self.dispatcher.addr, self.dispatcher.instruction_addrs[-1]):
            glue.add(i)  # to deal will jumps to the middle of the dispatcher block
        for addr in glue:
            node = self._get_tg_node(addr)
            for pred in self.func_cfg.transition_graph.predecessors(node):
                if pred.addr in self.dispatcher_chain:
                    continue
                pred = self.get_initial_node_before_calls(self._get_node(pred.addr))
                if not pred:
                    continue
                predecessors.add(pred.addr)
        return predecessors

    def get_next_state_value(self, state, addr=False) -> claripy.BVS:
        if not addr:
            addr = self.get_node_end(
                self.dispatcher
            )  # Running back to the dispatcher and getting state variable to map current state to next state
        self.proj.hook(addr, hook=self.extract_state_reg_hook)

        simgr_next_state = self.proj.factory.simgr(state)
        simgr_next_state.run(
            until=lambda sm: any(st.globals.get("stop_now") for st in sm.active)
        )
        state_val = self._state_value
        self._state_value = None
        self.proj.unhook(addr)
        return state_val

    def _get_supergraph_node(self, addr: int):
        """
        Resolve the SuperCFGNode for a given address with the following priority:
        1. Exact node.addr == addr
        2. Smallest node containing addr
        3. None if no match
        """
        matches = [n for n in self.supergraph.nodes if n.addr <= addr < n.addr + n.size]

        if not matches:
            return None

        for n in matches:
            if n.addr == addr:
                return n

        matched = min(matches, key=lambda n: n.size)
        if len(matches) > 1:
            raise ValueError
        return matched

    def non_call_predecessors(self, node, visited=None):
        """
        Return the real predecessors of `node`:
        - ignore call and fake_return edges
        - if only call-related predecessors exist, walk backward recursively
        """
        CALL_EDGE_TYPES = ("call", "fake_return")
        if visited is None:
            visited = set()
        # Prevent infinite loops
        if node in visited:
            return []

        visited.add(node)

        real_preds = []
        call_only_preds = []

        for src, _, data in self.transition_graph.in_edges(node, data=True):
            if data.get("type") in CALL_EDGE_TYPES:
                call_only_preds.append(src)
            else:
                real_preds.append(src)

        if real_preds:
            return real_preds

        preds = []
        for src in call_only_preds:
            preds.extend(self.non_call_predecessors(src, visited))

        return preds

    def get_state_reg(self) -> str:
        cfg = self.func_cfg
        counter = collections.Counter()
        for node in cfg.nodes:
            blk = self.proj.factory.block(node.addr, size=node.size)
            if len([i for i in blk.disassembly.insns if i.mnemonic != "nop"]) != 2:
                continue
            for insn in blk.capstone.insns:
                if insn.mnemonic != "cmp":
                    continue
                if len(insn.operands) != 2:
                    continue
                op0 = insn.operands[0]
                op1 = insn.operands[1]
                if op0.type != 1:  # reg enum
                    continue
                if op1.type != 2:  # imm enum
                    continue
                reg_name = insn.reg_name(op0.reg)
                counter[reg_name] += 1

        if not counter:
            raise FunctionNotFlattened(
                "Could not identify state register. Function may not be flattened"
            )

        self.state_reg = counter.most_common(1)[0][0]
        return self.state_reg

    def get_initial_node_before_calls(self, start_node):
        supernode = self._get_supergraph_node(start_node.addr)
        if not supernode:
            return None
        start_node = self._get_node(supernode.addr)
        return self.merge_calls(start_node)

    def walk_linear_cfg(
        self, start_node, stop_cond, max_steps=None
    ) -> list[angr.knowledge_plugins.cfg.cfg_node.CFGNode]:
        """
        Walk CFG successors linearly starting from start_node.

        :param start_node: angr CFGNode
        :param stop_cond: function(CFGNode) -> bool
        :param max_steps: optional safety bound
        :return: list[CFGNode]
        """
        visited = []
        cur = start_node
        steps = 0

        while cur is not None:
            visited.append(cur)
            succs = list(cur.successors)

            if len(succs) != 1:
                break

            fallthrough = None
            succs_jkinds = cur.successors_and_jumpkinds()
            for _, jumpkind in succs_jkinds:
                if jumpkind and "Ijk_Call" in str(jumpkind):
                    fallthrough = cur.addr + cur.size
            if fallthrough:
                cur = self._get_node(fallthrough)
                if stop_cond(cur):
                    visited.append(cur)
            else:
                cur = succs[0]

            if stop_cond(cur):
                break
            steps += 1
            if max_steps is not None and steps >= max_steps:
                break

        return visited

    def linear_walk_until_dispatcher(self, start: int) -> int:
        disp_chain = self.dispatcher_chain
        visited = self.walk_linear_cfg(
            self._get_node(start), lambda n: n.addr in disp_chain
        )
        node = visited[0]
        if len(visited) > 1:
            for n in visited[1:]:
                node = node.merge(n)

        orig_end = node.instruction_addrs[-1]
        raw = bytes(self.proj.loader.memory.load(orig_end, 10))
        insn = list(self.cs.disasm(raw, orig_end))[0]
        if insn.mnemonic[0] != "j":
            end = insn.address + insn.size
        else:
            end = orig_end

        raw = bytes(self.proj.loader.memory.load(end, 10))
        insn = list(self.cs.disasm(raw, end))[0]
        assert insn.mnemonic[0] == "j"
        return end

    def _get_node(self, addr: int) -> angr.knowledge_plugins.cfg.cfg_node.CFGNode:
        return self.master_cfg.model.get_any_node(addr, anyaddr=True)

    def get_node_end(self, node) -> int:
        blk = self.proj.factory.block(node.addr, size=node.size)
        insns = blk.capstone.insns
        last_insn = insns[-1]
        return last_insn.address

    def _get_tg_node(self, addr: int) -> angr.codenode.BlockNode:
        for n in self.transition_graph.nodes:
            if n.addr <= addr <= (n.addr + n.size - 1):
                return n
        return None

    def merge_calls(self, start_node) -> angr.knowledge_plugins.cfg.cfg_node.CFGNode:
        """
        Merges cfnodes so they are not split on calls.
        Project would have gone alot better if i created this immediately.
        """
        nodes = []
        final = start_node
        cur = start_node

        while True:
            succs = cur.successors_and_jumpkinds()
            if not succs:
                return final

            has_call = False
            fallthrough = None

            for succ, jumpkind in succs:
                if jumpkind and "Ijk_Call" in str(jumpkind):
                    has_call = True
                    fallthrough = self.master_cfg.model.get_any_node(
                        cur.addr + cur.size
                    )
            if not has_call:
                return final
            nodes.append(fallthrough)
            final = final.merge(fallthrough)
            cur = fallthrough

    def loop_hook(self, state):
        state.solver.add(state.regs.ebx <= 32)

    def hook_loops(self):
        """
        reg was used as loop counter and certain paths had this register unconstrained when entered.
        Caused Claripy to hang indefinetly. Couldn't fix by manually setting a state solver timeout.
        so just hooking the loops to have the registers constrained.
        Very brittle implementation atm - only rbx is detected as loop counter and jcc instruction
        has to be immediate successor.
        Add more logic as required.
        Also using threading exploration_tehcnique fixes this but it causes program to crash
        """
        addrs_to_hook = set()
        for block in self.func_cfg.blocks:
            insns = block.disassembly.insns

            for i, insn in enumerate(insns[:-1]):
                if insn.mnemonic != "dec":
                    continue

                if insn.operands[0].type != 1:  # REG
                    continue

                if insn.reg_name(insn.operands[0].reg) not in ("ebx", "rbx"):
                    continue

                next_insn = insns[i + 1]

                if CS_GRP_JUMP in next_insn.groups:
                    addrs_to_hook.add(next_insn.address)

        for i in addrs_to_hook:
            self.proj.hook(i, hook=self.loop_hook)

    def run(self) -> StateToNodeMapping:
        self.hook_loops()
        self.explore_unflattened_conditionals()
        self.explore_conditional_nodes()
        self.explore_dispatcher_entrances()
        self.explore_entry_nodes()
        self.explore_dispatcher_exits()
        return self.state_to_node_mapping
