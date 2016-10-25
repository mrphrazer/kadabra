from unicorn import *

from kadabra.utils.utils import addr_to_int, int_to_hex


def hook_mem_invalid(uc, access, address, size, value, emulator):
    if access == UC_MEM_WRITE_UNMAPPED or access == UC_MEM_READ_UNMAPPED:
        emulator.mem_map(address, size)
        return True
    else:
        return False


def hook_mem_access(uc, access, address, size, value, emu):
    current_address = emu.reg_read(emu.arch.IP)
    if access == UC_MEM_WRITE:
        value = value % (2 ** (size * 8))
        print "Instruction 0x{:x} writes value 0x{:x} with 0x{:x} bytes into 0x{:x}".format(current_address, value,
                                                                                   size, address)
        value = int_to_hex(value, size)
        emu.add_to_emulator_mem(address, value)

        return True
    else:
        value = addr_to_int(emu.mem_read(address, size))
        print "Instruction 0x{:x} reads value 0x{:x} with 0x{:x} bytes from 0x{:x}".format(current_address, value,
                                                                                           size, address)
        return True


def hook_code(uc, address, size, emu):
    opcode = emu.mem_read(address, size)
    print "0x{:x};{}".format(address, str(opcode).encode("hex"))

    # handle breakpoint
    if address in emu.breakpoints:
        emu.breakpoints[address](emu)



    return True


def hook_block(uc, address, size, user_data):
    print "Basic block at 0x{:x}".format(address)
    return True
