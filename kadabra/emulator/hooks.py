from unicorn import *


def hook_mem_invalid(uc, access, address, size, value, emulator):
    if access == UC_MEM_WRITE_UNMAPPED or access == UC_MEM_READ_UNMAPPED:
        emulator.mem_map(address, size)
        return True
    else:
        return False


def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        pass
    else:
        pass


def hook_code(uc, address, size, user_data):
    opcode = uc.mem_read(address, size)
    print "{};{}".format(hex(address), str(opcode).encode("hex"))


def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))
