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

                                      ("AX", (UC_X86_REG_AX, 16)),
                                      ("BX", (UC_X86_REG_BX, 16)),
                                      ("CX", (UC_X86_REG_CX, 16)),
                                      ("DX", (UC_X86_REG_DX, 16)),
                                      ("SI", (UC_X86_REG_SI, 16)),
                                      ("DI", (UC_X86_REG_DI, 16)),
                                      ("BP", (UC_X86_REG_BP, 16)),
                                      ("SP", (UC_X86_REG_SP, 16)),
                                      ("IP", (UC_X86_REG_IP, 16)),

                                      ("AL", (UC_X86_REG_AL, 8)),
                                      ("BL", (UC_X86_REG_BL, 8)),
                                      ("CL", (UC_X86_REG_CL, 8)),
                                      ("DL", (UC_X86_REG_DL, 8)),
                                      ("SIL", (UC_X86_REG_SIL, 8)),
                                      ("DIL", (UC_X86_REG_DIL, 8)),
                                      ("BPL", (UC_X86_REG_BPL, 8)),
                                      ("SPL", (UC_X86_REG_SPL, 8)),

                                      ("EFLAGS", (UC_X86_REG_EFLAGS, 32)),
                                      ])
