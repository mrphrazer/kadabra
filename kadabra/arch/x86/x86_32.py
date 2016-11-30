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

        self.registers = OrderedDict([("EAX", (UC_X86_REG_EAX, 32)),
                                      ("EBX", (UC_X86_REG_EBX, 32)),
                                      ("ECX", (UC_X86_REG_ECX, 32)),
                                      ("EDX", (UC_X86_REG_EDX, 32)),
                                      ("ESI", (UC_X86_REG_ESI, 32)),
                                      ("EDI", (UC_X86_REG_EDI, 32)),
                                      ("EBP", (UC_X86_REG_EBP, 32)),
                                      ("ESP", (UC_X86_REG_ESP, 32)),
                                      ("EIP", (UC_X86_REG_EIP, 32)),
                                      ("EFLAGS", (UC_X86_REG_EFLAGS, 32)),
                                      ])
