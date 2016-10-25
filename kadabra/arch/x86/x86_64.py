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

        self.registers = OrderedDict([("RAX", UC_X86_REG_RAX),
                                      ("RBX", UC_X86_REG_RBX),
                                      ("RCX", UC_X86_REG_RCX),
                                      ("RDX", UC_X86_REG_RDX),
                                      ("RSI", UC_X86_REG_RSI),
                                      ("RDI", UC_X86_REG_RDI),
                                      ("RBP", UC_X86_REG_RBP),
                                      ("RSP", UC_X86_REG_RSP),
                                      ("RIP", UC_X86_REG_RIP),
                                      ("R8", UC_X86_REG_R8),
                                      ("R9", UC_X86_REG_R9),
                                      ("R10", UC_X86_REG_R10),
                                      ("R11", UC_X86_REG_R11),
                                      ("R12", UC_X86_REG_R12),
                                      ("R13", UC_X86_REG_R13),
                                      ("R14", UC_X86_REG_R14),
                                      ("R15", UC_X86_REG_R15),
                                      ("RFLAGS", UC_X86_REG_EFLAGS),
                                      ])
