from collections import OrderedDict
from unicorn import UC_ARCH_X86, UC_MODE_64

from unicorn.x86_const import *


class X86_64:
    def __init__(self):
        self.SB = "RBP"
        self.SP = "RSP"
        self.IP = "RIP"
        self.FLAGS = "RFLAGS"
        self.uc_arch = UC_ARCH_X86
        self.uc_mode = UC_MODE_64

        self.size = 64

        self.registers = OrderedDict([("RAX", (UC_X86_REG_RAX, 64)),
                                      ("RBX", (UC_X86_REG_RBX, 64)),
                                      ("RCX", (UC_X86_REG_RCX, 64)),
                                      ("RDX", (UC_X86_REG_RDX, 64)),
                                      ("RSI", (UC_X86_REG_RSI, 64)),
                                      ("RDI", (UC_X86_REG_RDI, 64)),
                                      ("RBP", (UC_X86_REG_RBP, 64)),
                                      ("RSP", (UC_X86_REG_RSP, 64)),
                                      ("RIP", (UC_X86_REG_RIP, 64)),
                                      ("R8", (UC_X86_REG_R8, 64)),
                                      ("R9", (UC_X86_REG_R9, 64)),
                                      ("R10", (UC_X86_REG_R10, 64)),
                                      ("R11", (UC_X86_REG_R11, 64)),
                                      ("R12", (UC_X86_REG_R12, 64)),
                                      ("R13", (UC_X86_REG_R13, 64)),
                                      ("R14", (UC_X86_REG_R14, 64)),
                                      ("R15", (UC_X86_REG_R15, 64)),
                                      ("RFLAGS", (UC_X86_REG_EFLAGS, 64)),
                                      ])
