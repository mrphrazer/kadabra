from unicorn import *

from kadabra.utils.utils import addr_to_int, int_to_hex, to_unsinged


def hook_mem_invalid(uc, access, address, size, value, emulator):
    value = to_unsinged(value, size * 8)

    if access == UC_MEM_WRITE_UNMAPPED or access == UC_MEM_READ_UNMAPPED:
        emulator.mem_map(address, size)
        return True
    else:
        return False


def hook_mem_access(uc, access, address, size, value, emu):
    current_address = emu.reg_read(emu.arch.IP)
    value = to_unsinged(value, size * 8)

    if access == UC_MEM_WRITE:

        if emu.verbosity_level > 1:
            print "Instruction 0x{:x} writes value 0x{:x} with 0x{:x} bytes into 0x{:x}".format(current_address, value,
                                                                                                size, address)
        value_hex = int_to_hex(value, size)
        prev_value = addr_to_int(emu.mem_read(address, size)) if address in emu.memory else 0
        emu.add_to_emulator_mem(address, value_hex)

    else:
        value = addr_to_int(emu.mem_read(address, size))
        prev_value = value
        if emu.verbosity_level > 1:
            print "Instruction 0x{:x} reads value 0x{:x} with 0x{:x} bytes from 0x{:x}".format(current_address, value,
                                                                                               size, address)
    if emu.memory_trace:
        emu.memory_tracer.add_trace(current_address, access, address, prev_value, value, size)

    return True


def hook_code(uc, address, size, emu):
    opcode = str(emu.mem_read(address, size))
    if emu.verbosity_level > 1:
        print "0x{:x};{}".format(address, opcode.encode("hex"))

    # handle breakpoint
    if address in emu.breakpoints:
        call = emu.breakpoints[address](emu)

        # bp handler returns False
        if not call:
            emu.stop_execution()

    if emu.instruction_trace:
        emu.code_tracer.add_instruction_trace(address, opcode, size)

    return True


def hook_block(uc, address, size, emu):
    opcodes = str(emu.mem_read(address, size))

    if emu.verbosity_level > 1:
        print "Basic block at 0x{:x}".format(address)

    if emu.basic_block_trace:
        emu.code_tracer.add_basic_block_trace(address, opcodes, size)
    return True
