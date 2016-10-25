from kadabra.arch.arch_const import ARCH_X86_64
from kadabra.emulator.emulator import Emulator

code = ""
code += "\x55\x48\x89\xe5\x89\x7d\xec\x89\x75\xe8\x8b"
code += "\x45\xe8\x01\x45\xec\xd1\x65\xe8\x8b\x55\xec"
code += "\x8b\x45\xe8\x01\xd0\x3d\x38\x05\x00\x00\x75"
code += "\x14\xc7\x45\xfc\x00\x00\x00\x00\xc7\x45\xec"
code += "\x00\x00\x00\x00\x83\x45\xe8\x02\xeb\x20\xc7"
code += "\x45\xfc\x06\x00\x00\x00\x8b\x45\xe8\x01\x45"
code += "\xec\x8b\x55\xec\x8b\x45\xfc\x01\xd0\x85\xc0"
code += "\x75\x07\xb8\x00\x00\x00\x00\xeb\x05\xb8\x01"
code += "\x00\x00\x00\x5d\xc3"

def bp_test(emu):
    cur_addr = emu.reg_read(emu.arch.IP)

    print "Current address: 0x{:x}".format(cur_addr)

    return True

emu = Emulator(ARCH_X86_64)

START_ADDR = 0x1000000

emu.initialise_regs_random()
print emu.dump_registers()

emu.mem_map(START_ADDR, 2 * 1024 * 1024)

emu.mem_write(START_ADDR, code)

emu.add_hooks()

emu.reg_write("RBP", 0x11)
emu.reg_write("RSP", 0x222)

emu.add_breakpoint(0x1000001, bp_test)



emu.start_execution(START_ADDR, START_ADDR + len(code) - 1)

print emu.dump_registers()
