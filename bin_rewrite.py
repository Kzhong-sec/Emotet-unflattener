"""
Binary rewrite backend for control-flow unflattening.
Consumes a populated StateToNodeMapping instance which maps out the unflattenned control flow.

This module creates a new executable PE section named '.unflat' and rewrites
previously control-flow-flattened functions into this section in deobfuscated,
structured form.

High-level approach:
    1. A new executable and writable '.unflat' section is appended to the PE.
    2. Entire flattened functions are copied into this section.
    3. During copying:
        - All short conditional/unconditional branches and calls are expanded
          to guaranteed-size near branches using padding.
        - RIP-relative memory operands are fixed up to preserve semantics.
    4. Control-flow dispatch constructs (dispatcher jumps, flattened conditionals)
       are patched into direct control-flow edges between reconstructed basic blocks.
    5. The original function entry point is replaced with a trampoline jump into
       the rewritten version in '.unflat'.

Assumptions / constraints:
    - Target architecture is x86-64 PE (Windows).
    - Input binary is position-independent and uses RIP-relative addressing.

Output:
    - A new binary with '_unflat.bin' suffix containing:
        - Original code largely intact
        - Deobfuscated functions relocated into '.unflat'
        - Trampolines at original entries redirecting execution
"""

from capstone import *
from capstone.x86 import *
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_MODE_32
import lief

from graphs import StateToNodeMapping
from state_transitions import FunctionAnalyzer, AnalyzerContext


class BinaryRewriteContext:
    """
    Owns all binary‑wide state required for control‑flow rewriting.

    This class is responsible for:
        - Creating and managing the '.unflat' PE section
        - Assembling x86‑64 instructions using Keystone
        - Disassembling instructions for relocation analysis via Capstone
        - Applying patches and trampolines to the target binary
        - Preserving an untouched copy of the original PE for reference

    The rewrite context is shared across all rewritten functions in a binary.
    It provides utilities for:
        - Emitting new code into the '.unflat' section
        - Copying and relocating original code while preserving semantics
        - Resolving runtime virtual addresses (VA) correctly

    This class does not perform control‑flow analysis. It strictly consumes
    analysis results and applies concrete binary modifications.
    """

    def __init__(self, fpath, analyzer_ctx: AnalyzerContext):
        self.fpath = fpath
        self._create_section()
        self.section_offset = 0
        self.pe: lief._lief.PE.Binary
        if analyzer_ctx.bitness == 64:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        elif analyzer_ctx.bitness == 32:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.cs.detail = True
        self._orig_pe: (
            lief._lief.PE.Binary
        )  # need an original copy that is not effected by patches.
        self.unflat_section_size = 0

    @property
    def section_file_pointer(self):
        va = self.section.virtual_address + self.section_offset + self.pe.imagebase
        return va

    @property
    def section(self):
        return self.pe.get_section(".unflat")

    def _create_section(self) -> lief._lief.PE.Section:
        pe = lief.parse(self.fpath)
        unflat_section_size = pe.get_section(".text").virtual_size * 2
        self.unflat_section_size = unflat_section_size
        section = lief.PE.Section(".unflat")
        section.content = list([0x90] * unflat_section_size)
        section.characteristics = (
            section.CHARACTERISTICS.MEM_READ
            | section.CHARACTERISTICS.MEM_WRITE
            | section.CHARACTERISTICS.MEM_EXECUTE
        )
        self.pe = pe

        pe.add_section(section)
        self._orig_pe = lief.parse(self.fpath)
        return section

    def write_bin(self, fpath_out=None):
        if fpath_out == None:
            new_name = self.fpath + ".unflattened"
        else:
            new_name = fpath_out
        self.pe.write(new_name)
        print(f"Wrote new bin at {new_name}")

    def write_jmp_insn_with_padding(self, code_str: str, va: int):
        """
        need padding incase our near jumps turns into a short jump
        """
        PADDING_SIZE = 6
        code = self._assemble_at(code_str, va)
        if len(code) > PADDING_SIZE:
            raise RuntimeError(f"Oversized branch at {code_str})")
        code += b"\x90" * (PADDING_SIZE - len(code))
        self.pe.patch_address(va, list(code))

    def emit_unflat_section(self, code_str: str) -> int:
        """
        Assemble code_str, write it into the current .unflat section offset,
        update the section cursor, and return the runtime VA of the first instruction.
        """
        va = self.section_file_pointer

        code = self._assemble_at(code_str, va)

        if self.section_offset + len(code) > len(self.section.content):
            raise RuntimeError("Not enough space left in .unflat section")

        self.pe.patch_address(va, list(code))
        self.section_offset += len(code)
        return va

    def format_disp(self, d):
        if d >= 0:
            return f"+ 0x{d:x}"
        else:
            return f"- 0x{-d:x}"

    def rewrite_with_padding(self, start: int, end: int):
        """
        Copies an instruction range into .unflat section, rewriting:
        - all jmp / jcc / call instructions with enough following padding to convert them into near jmps
        - fix RIP-relative memory operands

        Returns:
            (new_entry_va, instruction_map)
            instruction_map: { original_insn_va : relocated_insn_va }
        """

        PADDING_SIZE = 6

        raw = bytes(self._orig_pe.get_content_from_virtual_address(start, end - start))

        cs = self.cs
        ks = self.ks

        # PASS 1: decode all instructions

        instructions = []
        for insn in cs.disasm(raw, start):
            if insn.address >= end:
                break
            instructions.append(insn)

        # PASS 2: layout planning using Keystone sizes

        instruction_map = {}
        new_cursor = self.section_file_pointer
        new_func_entry = new_cursor

        for insn in instructions:
            instruction_map[insn.address] = new_cursor

            asm = insn.mnemonic
            if insn.op_str:
                asm += " " + insn.op_str

            if insn.group(CS_GRP_JUMP):
                if insn.size > PADDING_SIZE:
                    raise RuntimeError(
                        f"Oversized branch at {hex(insn.address)} during layout"
                    )
                new_cursor += PADDING_SIZE
            else:
                encoding, _ = ks.asm(asm, new_cursor)
                size = len(encoding)
                new_cursor += size

        # PASS 3: emit rewritten code

        for insn in instructions:
            new_addr = instruction_map[insn.address]

            asm = insn.mnemonic
            if insn.op_str:
                asm += " " + insn.op_str

            # Fix RIP-relative memory
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    disp = op.mem.disp
                    old = self.format_disp(disp)

                    orig_target = insn.address + insn.size + disp
                    new_rip = new_addr  # keystone computes RIP internally
                    new_disp = orig_target - (new_rip + insn.size)
                    new = self.format_disp(new_disp)

                    asm = asm.replace(old, new)
                    break

            # Rewrite jmp / Jcc / CALL
            if (insn.group(CS_GRP_JUMP) or insn.mnemonic == "call") and insn.operands:
                op = insn.operands[0]
                if op.type == X86_OP_IMM:
                    orig_dst = op.imm
                    new_dst = instruction_map.get(orig_dst, orig_dst)
                    asm = f"{insn.mnemonic} {hex(new_dst)}"

            encoding, _ = ks.asm(asm, new_addr)
            code = bytes(encoding)

            if insn.group(CS_GRP_JUMP):
                if len(code) > PADDING_SIZE:
                    raise RuntimeError(f"Oversized branch at {hex(insn.address)}")
                code += b"\x90" * (PADDING_SIZE - len(code))
            self.pe.patch_address(new_addr, list(code))
            self.section_offset += len(code)

        return new_func_entry, instruction_map

    def _assemble_at(self, code_str: str, va: int) -> bytes:
        encoding, _ = self.ks.asm(code_str, va)
        return bytes(encoding)

    def FunctionRewriter(self, stm, analyzer) -> FunctionRewriter:
        func_rewriter = FunctionRewriter(stm, analyzer, self)
        return func_rewriter


class FunctionRewriter:
    """
    Applies control‑flow rewriting for a single flattened function.

    This class consumes:
        - A populated StateToNodeMapping describing reconstructed control flow
        - The corresponding function analysis object
        - A BinaryRewriteContext for code emission and patching

    Responsibilities:
        - Relocate the original function body into the '.unflat' section
        - Patch dispatcher exits into direct control‑flow transfers
        - Replace flattened dispatcher entrances with direct jumps
        - Rewrite conditional state‑based transitions into explicit branches
        - Install a trampoline at the original function entry point

    The rewritten function preserves original semantics while eliminating
    control‑flow flattening, producing a structured CFG suitable for
    disassembly and decompilation.
    """

    def __init__(
        self,
        stm: StateToNodeMapping,
        analyzer: FunctionAnalyzer,
        ctx: BinaryRewriteContext,
    ):
        self.ctx = ctx
        self.stm = stm
        self.analyzer = analyzer
        if analyzer.parent.bitness == 64:
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        elif analyzer.parent.bitness == 32:
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.instruction_map = None  # allows for mapping of instruction addresses in original function to the rewritten function in the .unflat section
        self.state_to_entrance = {}
        for addr, state in stm.dispatcher_exits.items():
            state = list(state)[0]
            self.state_to_entrance[state] = addr

    def check_original_bb_insns(self, loc: int):
        """
        Supply the address of the location of the original jump back into the dispatcher.
        This will check if the destination contains any non dispatcher instructions.
        This is because the start of the dispatcher would have an instruction that was actually part
        of an original basic block which I clasified as a dispatcher instruction.
        """
        loc = self.get_imm_jump_target(loc)
        if loc not in self.analyzer.dispatcher_chain:
            return ""
        block = self.analyzer.func_cfg.get_block(loc)
        orig_bb_insns = ""
        for insn in block.disassembly.insns:
            if insn.mnemonic[0] == "j":
                break
            if insn.mnemonic == "cmp":
                reg_name = insn.reg_name(insn.operands[0].reg)
                if reg_name == self.analyzer.state_reg:
                    break
            if insn.op_str:
                asm = f"{insn.mnemonic} {insn.op_str}\n"
            else:
                asm = insn.mnemonic + "\n"

            orig_bb_insns += asm
        return orig_bb_insns

    def get_imm_jump_target(self, addr):
        raw = bytes(self.ctx._orig_pe.get_content_from_virtual_address(addr, addr + 10))
        insn = list(self.ctx.cs.disasm(raw, addr))[0]
        if insn.mnemonic[0] != "j":
            return None
        op = insn.operands[0]
        assert op.type == CS_OP_IMM
        target = op.imm
        return target

    def patch_unflattended_conditionals(self):
        for jmp_addr, state in self.stm.unflat_conditionals.items():
            state = state[0]
            raw = bytes(
                self.ctx._orig_pe.get_content_from_virtual_address(
                    jmp_addr, jmp_addr + 10
                )
            )
            insn = list(self.ctx.cs.disasm(raw, jmp_addr))[0]
            assert insn.mnemonic[0] == "j"
            orig_insns = self.check_original_bb_insns(jmp_addr)
            jmp_addr = self.instruction_map[jmp_addr]

            dst = self.state_to_entrance[state]
            dst = self.instruction_map[dst]
            instrumented = f"{insn.mnemonic} {hex(dst)}"

            if (
                orig_insns
            ):  # need to implement a trampoline if original instructions are present at the jump address
                instrumented_code_start = self.ctx.section_file_pointer
                self.ctx.write_jmp_insn_with_padding(
                    f"jmp {hex(instrumented_code_start)}", jmp_addr
                )  # jump to my instrumented trampoline, instead of just jumping to the next block
                instrumented = orig_insns + instrumented
                self.ctx.emit_unflat_section(
                    instrumented
                )  # rewrite original instructions, then jump to the next intended block
            else:
                self.ctx.write_jmp_insn_with_padding(instrumented, jmp_addr)

    def patch_dispatcher_entrances(self):
        for jmp_addr, state in self.stm.dispatcher_entrance.items():
            state = state[0]
            orig_insns = self.check_original_bb_insns(jmp_addr)
            jmp_addr = self.instruction_map[jmp_addr]
            dst = self.state_to_entrance[state]
            self.check_original_bb_insns(dst)
            dst = self.instruction_map[dst]
            instrumented = f"jmp {hex(dst)}"
            if (
                orig_insns
            ):  # need to implement a trampoline if original instructions are present at the jump address
                instrumented_code_start = self.ctx.section_file_pointer
                self.ctx.write_jmp_insn_with_padding(
                    f"jmp {hex(instrumented_code_start)}", jmp_addr
                )  # jump to my instrumented trampoline, instead of just jumping to the next block
                instrumented = orig_insns + instrumented
                self.ctx.emit_unflat_section(
                    instrumented
                )  # rewrite original instructions, then jump to the next intended block
            else:
                self.ctx.write_jmp_insn_with_padding(instrumented, jmp_addr)

    def patch_conditional_nodes(self):
        for jmp_addr, next_states in self.stm.conditional_jmps.items():
            next_states = list(next_states)
            instrumented_code_start = self.ctx.section_file_pointer
            orig_insns = self.check_original_bb_insns(jmp_addr)
            jmp_addr = self.instruction_map[jmp_addr]
            self.ctx.write_jmp_insn_with_padding(
                f"jmp {hex(instrumented_code_start)}", jmp_addr
            )
            instrumented = ""
            for n in next_states[:-1]:
                dst = self.state_to_entrance[n]
                self.check_original_bb_insns(dst)
                dst = self.instruction_map[dst]
                instrumented += f"cmp {self.analyzer.state_reg}, {n}\njz {hex(dst)}\n"
            dst = self.state_to_entrance[next_states[-1]]
            dst = self.instruction_map[dst]
            instrumented += f"jmp {hex(dst)}"  # need to finish chain with an unconditional jump or the decompilation/ dissasembly from IDA will look bad
            if (
                orig_insns
            ):  # need to implement a trampoline if original instructions are present at the jump address
                instrumented_code_start = self.ctx.section_file_pointer
                self.ctx.write_jmp_insn_with_padding(
                    f"jmp {hex(instrumented_code_start)}", jmp_addr
                )  # jump to my instrumented trampoline, instead of just jumping to the next block
                instrumented = orig_insns + instrumented
                self.ctx.emit_unflat_section(
                    instrumented
                )  # rewrite original instructions, then jump to the next intended block
            else:
                self.ctx.emit_unflat_section(instrumented)

    def get_function_end(self):
        """
        address after last instruction
        """
        func_addr = self.analyzer.func_addr
        func_obj = self.analyzer.master_cfg.functions[func_addr]
        last_block = max(list(func_obj.block_addrs_set))
        last_block = self.analyzer.proj.factory.block(last_block)
        end = last_block.capstone.insns[-1].address + last_block.capstone.insns[-1].size
        return end

    def run(self):
        func_addr = self.analyzer.func_addr
        end = self.get_function_end()
        new_va_start, instruction_map = self.ctx.rewrite_with_padding(func_addr, end)
        self.ctx.write_jmp_insn_with_padding(
            f"jmp {hex(new_va_start)}", func_addr
        )  # trampoline from original function to copied function in .unflat section
        self.instruction_map = instruction_map
        self.patch_unflattended_conditionals()
        self.patch_dispatcher_entrances()
        self.patch_conditional_nodes()
