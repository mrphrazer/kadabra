from collections import namedtuple, deque
from unicorn import UC_MEM_READ, UC_MEM_WRITE


class MemoryTracer(deque):
    def __init__(self):
        super(MemoryTracer, self).__init__()
        self._instr_to_mem_states = dict()

    def gen_trace_state(self, instr_addr, access, mem_addr, value, size):
        state = namedtuple("TraceState", 'instr_addr, access, mem_addr, value, size')

        state.instr_addr = instr_addr
        state.access = access
        state.mem_addr = mem_addr
        state.value = value
        state.size = size

        return state

    def add_trace(self, instr_addr, access, mem_addr, value, size):
        state = self.gen_trace_state(instr_addr, access, mem_addr, value, size)

        self.append(state)

        if state.instr_addr not in self._instr_to_mem_states:
            self._instr_to_mem_states[state.instr_addr] = []
        self._instr_to_mem_states[state.instr_addr].append(state)

    def get_mem_states(self, addr):
        if addr in self._instr_to_mem_states:
            return self._instr_to_mem_states[addr]


class CodeTracer(object):
    def __init__(self):
        self.instruction_trace = deque()
        self.basic_block_trace = deque()

    def gen_instruction_state(self, addr, opcode, size):
        state = namedtuple("InstructionState", 'address, opcode, size')

        state.address = addr
        state.opcode = opcode
        state.size = size

        return state

    def gen_basic_block_state(self, addr, opcodes, size):
        state = namedtuple("BasicBlockState", 'address, opcodes, size')

        state.address = addr
        state.opcodes = opcodes
        state.size = size

        return state

    def add_instruction_trace(self, address, opcode, size):
        state = self.gen_instruction_state(address, opcode, size)
        self.instruction_trace.append(state)

    def add_basic_block_trace(self, address, opcodes, size):
        state = self.gen_basic_block_state(address, opcodes, size)
        self.basic_block_trace.append(state)

    def reset_instruction_trace(self):
        self.instruction_trace = deque()

    def reset_basic_block_trace(self):
        self.basic_block_trace = deque()
