from capstone.x86_const import *

from .utils import get_reg, dbg_print, get_bitness, get_reg_size
from .encoding import ModRm, Sib, Displacement


OPERAND_MODRM_REG = 0
OPERAND_MODRM_RM = 1
OPERAND_SIB = 2
OPERAND_IMM = 3
OPERAND_DISP = 4


class OperandLocator:
    """Map capstone operands to raw operands"""
    def __init__(self, instr, modrm: ModRm, sib: Sib, disp: Displacement):
        self._instr = instr

        self._mapping = [None, None, None, None, None]

        self._modrm = modrm
        self._sib = sib
        self._disp = disp

        if len(instr.operands) > len(self._mapping):
            print(f"[!] Instruction at '{self._instr.address:08X}' have too much operands. Operands Locating failed")
            return

        dbg_print(f"Locator NO: {len(self._instr.operands)}")
        for operand in self._instr.operands:
            if operand.type == X86_OP_IMM:
                self._mapping[OPERAND_IMM] = operand
                continue

            if self._modrm and self._modrm.is_only_reg() and not self.locate(OPERAND_MODRM_RM):
                if operand.type == X86_OP_REG:

                    modrm_reg = get_reg(self._modrm.rm_id, get_reg_size(operand.reg), instr)

                    if operand.reg == modrm_reg:
                        dbg_print("_modrm + is_only_reg() -> OPERAND_MODRM_RM")
                        self._mapping[OPERAND_MODRM_RM] = operand
                        continue

            if self._modrm and self._modrm.is_mem_with_rm_base_reg() and not self.locate(OPERAND_MODRM_RM) \
                    and get_reg_size(operand.mem.base):

                if operand.type == X86_OP_MEM:
                    modrm_reg = get_reg(self._modrm.rm_id, get_reg_size(operand.mem.base), instr)

                    if operand.mem.base == modrm_reg:
                        dbg_print("_modrm + is_mem_with_rm_base_reg() -> OPERAND_MODRM_RM")
                        self._mapping[OPERAND_MODRM_RM] = operand
                        continue

            if self._modrm and self._modrm.is_mem_with_sib() and not self.locate(OPERAND_SIB)\
                    and self._sib.is_mem_with_base_reg():
                sib_base_reg = get_reg(self._sib.base_id, get_bitness(), instr)

                if operand.type == X86_OP_MEM and operand.mem.base == sib_base_reg:
                    dbg_print("_modrm + is_mem_with_sib() -> OPERAND_SIB")

                    self._mapping[OPERAND_SIB] = operand
                    continue

            if self._modrm and self._modrm.is_mem_with_sib() and not self.locate(OPERAND_SIB) \
                    and self._sib.is_mem_with_only_index_disp_32():

                sib_index_reg = get_reg(self._sib.index_id, get_bitness(), instr)

                if operand.type == X86_OP_MEM and operand.mem.index == sib_index_reg:
                    dbg_print("_modrm + is_mem_with_sib() -> OPERAND_SIB")

                    self._mapping[OPERAND_SIB] = operand
                    continue

            if not self._modrm and not self._sib and self._disp and operand.type == X86_OP_MEM and \
                    self._disp.disp == operand.mem.disp:
                dbg_print("not _modrm + not _sib (only disp) -> OPERAND_DISP")
                self._mapping[OPERAND_DISP] = operand
                continue

            if self._modrm and self._modrm.is_mem_rip_rel():
                dbg_print("_modrm +  is_mem_rip_rel() -> OPERAND_DISP")
                self._mapping[OPERAND_DISP] = operand
                continue

            if self._modrm and operand.type == X86_OP_REG and get_reg_size(operand.reg):

                modreg_reg = get_reg(self._modrm.reg_id, get_reg_size(operand.reg), instr)

                if operand.reg == modreg_reg and not self.locate(OPERAND_MODRM_REG):
                    dbg_print("modreg_reg -> OPERAND_MODRM_REG")
                    self._mapping[OPERAND_MODRM_REG] = operand
                    continue

        dbg_print(f"OPERAND_MODRM_REG: {self.locate(OPERAND_MODRM_REG)}")
        dbg_print(f"OPERAND_MODRM_RM: {self.locate(OPERAND_MODRM_RM)}")
        dbg_print(f"OPERAND_SIB: {self.locate(OPERAND_SIB)}")
        dbg_print(f"OPERAND_IMM: {self.locate(OPERAND_IMM)}")
        dbg_print(f"OPERAND_MODRM_REG: {self.locate(OPERAND_DISP)}")

    def locate(self, id: int):
        if id >= len(self._mapping):
            return None

        return self._mapping[id]
