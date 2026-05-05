"""
This module defines the mapping between flattened control-flow states and
their corresponding basic block entry points in the original function.
Populated by an Analyzer instance within calc_transition.py


Three distinct patterns for entering the dispatcher were identified during
analysis of flattened functions:

1) Dispatcher entrance
   A direct unconditional jump to the dispatcher, immediately preceded by
   assigning an immediate value to the state register.

   Example pattern:
       mov STATE_REG, IMM
       jmp dispatcher

   Represented by: dispatcher_entrance

2) Conditional dispatcher jump
   A direct unconditional jump to the dispatcher, where the state register
   is conditionally assigned one of two or more possible values. This is
   implemented either via cmovcc instructions or an instruction sequence
   equivalent to:

       neg     reg
       sbb     STATE_REG, STATE_REG
       and     STATE_REG, imm
       add     STATE_REG, imm

   Represented by: conditional_jmps

3) Unflattened conditional
   A conditional branch (jcc) preceded by assignment of an immediate state
   value, where the taken branch enters the dispatcher and the fallthrough
   path continues executing original (unflattened) basic-block code.

   Represented by: unflat_conditionals

Additionally, dispatcher exits are tracked, which correspond to jump sites
inside the dispatcher that transfer control to original basic blocks based
on the resolved state value.
"""


class StateToNodeMapping:
    """
    Stores relationships between flattened control-flow states and original
    basic block entry points discovered during unflattening analysis.

    All mappings are keyed by instruction addresses (virtual addresses in
    the original binary), and map to one or more possible next state values.

    Mapping categories:

    - conditional_jmps:
        Jump sites where multiple possible next states may be selected
        conditionally before an unconditional jump to the dispatcher.

        { jmp_addr -> [state1, state2, ...] }

    - dispatcher_entrance:
        Direct jumps to the dispatcher following an unconditional assignment
        of a single immediate state value.

        { jmp_addr -> [state] }

    - unflat_conditionals:
        Conditional jumps where only the taken branch enters the dispatcher.
        The fallthrough path continues with original (unflattened) code.

        { jmp_addr -> [state] }

    - dispatcher_exits:
        Jump sites inside the dispatcher that exit into original basic blocks
        after state resolution.

        { jmp_addr -> [state] }

    Internally, duplicate states per jump site are prevented while preserving
    insertion order.
    """

    def __init__(self):
        self.conditional_jmps: dict[int, list[int]] = {}
        self._conditional_seen: dict[int, set[int]] = {}

        self.dispatcher_entrance: dict[int, list[int]] = {}
        self._dispatcher_entrance_seen: dict[int, set[int]] = {}

        self.unflat_conditionals: dict[int, list[int]] = {}
        self._unflat_conditionals_seen: dict[int, set[int]] = {}

        self.dispatcher_exits: dict[int, list[int]] = {}
        self._dispatcher_exits_seen: dict[int, set[int]] = {}

    def move_dispatcher_entrance_to_conditional(self, jmp_addr: int):
        """
        Move a dispatcher_entrance entry to conditional_jmps.
        """
        if jmp_addr not in self.dispatcher_entrance:
            return

        self.conditional_jmps.setdefault(jmp_addr, [])
        self._conditional_seen.setdefault(jmp_addr, set())

        for state in self.dispatcher_entrance[jmp_addr]:
            if state not in self._conditional_seen[jmp_addr]:
                self._conditional_seen[jmp_addr].add(state)
                self.conditional_jmps[jmp_addr].append(state)

        del self.dispatcher_entrance[jmp_addr]
        self._dispatcher_entrance_seen.pop(jmp_addr, None)

    def add_conditional_jump(self, jmp_addr: int, next_state: int):
        self.conditional_jmps.setdefault(jmp_addr, [])
        self._conditional_seen.setdefault(jmp_addr, set())

        if next_state not in self._conditional_seen[jmp_addr]:
            self._conditional_seen[jmp_addr].add(next_state)
            self.conditional_jmps[jmp_addr].append(next_state)

    def add_dispatcher_entrance(self, jmp_addr: int, next_state: int):
        self.dispatcher_entrance.setdefault(jmp_addr, [])
        self._dispatcher_entrance_seen.setdefault(jmp_addr, set())

        if next_state not in self._dispatcher_entrance_seen[jmp_addr]:
            self._dispatcher_entrance_seen[jmp_addr].add(next_state)
            self.dispatcher_entrance[jmp_addr].append(next_state)

    def add_unflat_conditional(self, jmp_addr: int, next_state: int):
        self.unflat_conditionals.setdefault(jmp_addr, [])
        self._unflat_conditionals_seen.setdefault(jmp_addr, set())

        if next_state not in self._unflat_conditionals_seen[jmp_addr]:
            self._unflat_conditionals_seen[jmp_addr].add(next_state)
            self.unflat_conditionals[jmp_addr].append(next_state)

    def add_dispatcher_exit(self, jmp_addr: int, next_state: int):
        self.dispatcher_exits.setdefault(jmp_addr, [])
        self._dispatcher_exits_seen.setdefault(jmp_addr, set())

        if next_state not in self._dispatcher_exits_seen[jmp_addr]:
            self._dispatcher_exits_seen[jmp_addr].add(next_state)
            self.dispatcher_exits[jmp_addr].append(next_state)

    def __repr__(self) -> str:
        lines = []

        def dump_section(title: str, mapping: dict[int, list[int]]):
            lines.append(f"{title}:")
            for k, v in mapping.items():
                lines.append(f"  {hex(k)} {v}")

        dump_section("Conditional jumps", self.conditional_jmps)
        dump_section("Dispatcher entrances", self.dispatcher_entrance)
        dump_section("Unflat conditionals", self.unflat_conditionals)
        dump_section("Dispatcher exits", self.dispatcher_exits)

        return "\n".join(lines)
