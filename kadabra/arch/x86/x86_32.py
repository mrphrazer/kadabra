from collections import OrderedDict
from unicorn import UC_ARCH_X86, UC_MODE_32

from unicorn.x86_const import *


class X86_32:
    def __init__(self):
        self.SB = "EBP"
        self.SP = "ESP"
        self.IP = "EIP"
        self.FLAGS = "EFLAGS"
        self.uc_arch = UC_ARCH_X86
        self.uc_mode = UC_MODE_32

        self.size = 32

        self.registers = OrderedDict([("EAX", UC_X86_REG_EAX),
                                      ("EBX", UC_X86_REG_EBX),
                                      ("ECX", UC_X86_REG_ECX),
                                      ("EDX", UC_X86_REG_EDX),
                                      ("ESI", UC_X86_REG_ESI),
                                      ("EDI", UC_X86_REG_EDI),
                                      ("EBP", UC_X86_REG_EBP),
                                      ("ESP", UC_X86_REG_ESP),
                                      ("EIP", UC_X86_REG_EIP),
                                      ("EFLAGS", UC_X86_REG_EFLAGS),
                                      ])
