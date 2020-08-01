import idautils

from binascii import hexlify

from .locator import *
from .utils import SettingsDialog, is_gp_reg, is_stack_reg, TEMPLATE_SYMBOL, get_bitness, dbg_print, __debugmode__


class OperandParameterizer:
    def __init__(self, instr):
        self._instr = instr

        if __debugmode__:
            c = -1
            for operand in instr.operands:
                c += 1
                if operand.type == X86_OP_REG:
                    dbg_print("\t\toperands[%u].type: REG = %s" % (c, instr.reg_name(operand.reg)))
                if operand.type == X86_OP_IMM:
                    dbg_print("\t\toperands[%u].type: IMM = 0x%s" % (c, hex(operand.imm)))
                if operand.type == X86_OP_MEM:
                    dbg_print("\t\toperands[%u].type: MEM" % c)
                    if operand.mem.segment != 0:
                        dbg_print("\t\t\toperands[%u].mem.segment: REG = %s" % (c, instr.reg_name(operand.mem.segment)))
                    if operand.mem.base != 0:
                        dbg_print("\t\t\toperands[%u].mem.base: REG = %s" % (c, instr.reg_name(operand.mem.base)))
                    if operand.mem.index != 0:
                        dbg_print("\t\t\toperands[%u].mem.index: REG = %s" % (c, instr.reg_name(operand.mem.index)))
                    if operand.mem.scale != 1:
                        dbg_print("\t\t\toperands[%u].mem.scale: %u" % (c, operand.mem.scale))
                    if operand.mem.disp != 0:
                        dbg_print("\t\t\toperands[%u].mem.disp: 0x%s" % (c, hex(operand.mem.disp)))

        R = 0
        B = 0
        X = 0
        if instr.rex:
            prefix = instr.rex & 0xf

            R = (prefix & 4) >> 2
            B = prefix & 1
            X = (prefix & 2) >> 1

        self.modrm: ModRm = None
        self.sib: Sib = None
        self.disp: Displacement = None

        if instr.modrm:
            self.modrm: ModRm = ModRm.from_instr(self._instr, R, B)
            if __debugmode__:
                self.modrm.print()

        if self.modrm and self.modrm.is_mem_with_sib():
            self.sib = Sib.from_instr(self._instr, self.modrm.mod, X, B)
            if __debugmode__:
                self.sib.print()

        if instr.disp:
            self.disp = Displacement.from_instr(instr, self.modrm, self.sib)
            if __debugmode__:
                self.disp.print()

        self.locator = OperandLocator(instr, self.modrm, self.sib, self.disp)

    def parameterize_modrm_byte(self, settings: SettingsDialog) -> str:
        """
        Parameterize Mod R/M byte
        :param settings: Settings instance
        :return: (str) Parameterized pattern of the Mod R/M byte
        """
        i = 0
        reg_op = self.locator.locate(OPERAND_MODRM_REG)

        if reg_op and is_stack_reg(reg_op.reg) and settings.cSRegistersParam.checked and reg_op.reg in settings.sp_regs:
            i = 1

        if reg_op and is_gp_reg(reg_op.reg) and settings.cGpRegistersParam.checked and reg_op.reg in settings.gp_regs:
            i = 1

        j = 0
        rm_op = self.locator.locate(OPERAND_MODRM_RM)

        if rm_op and rm_op.type == X86_OP_REG:
            if is_stack_reg(rm_op.reg) and settings.cSRegistersParam.checked and rm_op.reg in settings.sp_regs:
                j = 1

            if is_gp_reg(rm_op.reg) and settings.cGpRegistersParam.checked and rm_op.reg in settings.gp_regs:
                j = 1

        if rm_op and self.modrm.is_mem_with_rm_base_reg():
            if is_stack_reg(rm_op.mem.base) and settings.cSRegistersParam.checked \
                    and rm_op.mem.base in settings.sp_regs:
                j = 1

            if is_gp_reg(rm_op.mem.base) and settings.cGpRegistersParam.checked and rm_op.mem.base in settings.gp_regs:
                j = 1

        # The following code are using a special matrix (2X2) to resolve a operation applied to Mod R/M
        # You can read i and j as "We spin a value of R/M if value of j true"
        # and "We spin a value of Reg if value of i true"
        return self.modrm.parameterize(i, j, settings)

    def parameterize_sib_byte(self, settings: SettingsDialog):
        """
        Parameterize Scale/Index/Base byte
        :param settings: Settings instance
        :return: (str) Parameterized pattern of the SIB byte
        """
        sib_op = self.locator.locate(OPERAND_SIB)

        if sib_op is None:
            print(f"[!] {self._instr.address:08X}: Match operands to Sib data failed! Used default template")
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}"

        j = 0
        if self.sib.is_mem_with_base_reg() and is_stack_reg(sib_op.mem.base) and settings.cSRegistersParam.checked \
                and sib_op.mem.base in settings.sp_regs:
            j = 1

        if self.sib.is_mem_with_base_reg() and is_gp_reg(sib_op.mem.base) and settings.cGpRegistersParam.checked \
                and sib_op.mem.base in settings.gp_regs:
            j = 1

        i = 0
        if self.sib.is_mem_with_index() and is_stack_reg(sib_op.mem.index) and settings.cSRegistersParam.checked \
                and sib_op.mem.index in settings.sp_regs:
            i = 1

        if self.sib.is_mem_with_index() and is_gp_reg(sib_op.mem.index) and settings.cGpRegistersParam.checked \
                and sib_op.mem.index in settings.gp_regs:
            i = 1

        # i, j means the same things as for Mod R/M
        return self.sib.parameterize(i, j, settings)

    def parameterize_disp(self, settings: SettingsDialog):
        """
        Parameterize displacement value
        :param settings: Settings instance
        :return: (str) Parameterized pattern of the displacement value
        """
        disp_off = self._instr.disp_offset
        disp_size = self._instr.disp_size

        rm_op = self.locator.locate(OPERAND_MODRM_RM)

        if rm_op and self.modrm.is_mem_with_rm_base_reg_and_disp() and is_gp_reg(
                rm_op.mem.base) and settings.cGpDisplacementParam.checked:
            dbg_print("parameterize_disp(): rm_base_reg_and_disp + gp_reg")
            return self.disp.parameterize_default(settings)

        if rm_op and self.modrm.is_mem_with_rm_base_reg_and_disp() and is_stack_reg(
                rm_op.mem.base) and settings.cSDisplacementParam.checked:
            dbg_print("parameterize_disp(): rm_base_reg_and_disp + sp_reg")
            return self.disp.parameterize_default(settings)

        sib_op = self.locator.locate(OPERAND_SIB)

        if sib_op and self.modrm.is_mem_with_sib_and_disp() and is_gp_reg(
                sib_op.mem.base) and settings.cGpDisplacementParam.checked:
            dbg_print("parameterize_disp(): sib_and_disp + gp_reg")
            return self.disp.parameterize_default(settings)

        if sib_op and self.modrm.is_mem_with_sib_and_disp() and is_stack_reg(
                sib_op.mem.base) and settings.cSDisplacementParam.checked:
            dbg_print("parameterize_disp(): sib_and_disp + sp_reg")
            return self.disp.parameterize_default(settings)

        disp_op = self.locator.locate(OPERAND_DISP)

        if disp_op and not self.modrm and not self.sib:
            dbg_print("parameterize_disp(): only_disp (address)")
            return self.disp.parameterize_address(settings)

        if self.modrm and self.modrm.is_mem_rip_rel():
            if get_bitness() == 32:
                dbg_print("parameterize_disp(): only_disp_rip_rel (address)")
                return self.disp.parameterize_address(settings)
            else:
                dbg_print("parameterize_disp(): only_disp_rip_rel (offset)")
                return self.disp.parameterize_offset(settings)

        return hexlify(self._instr.bytes[disp_off: disp_off + disp_size]).decode('utf-8').upper()

    def parameterize_imm(self, settings: SettingsDialog):
        """
        Parameterize immediate value
        :param settings: Settings instance
        :return: (str) Parameterized pattern of the immediate value
        """

        imm_offset = self._instr.imm_offset
        imm_size = self._instr.imm_size
        imm_data = self._instr.bytes[imm_offset: imm_offset + imm_size]

        imm_op = self.locator.locate(OPERAND_IMM)

        if not imm_op:
            print(f"[!] {self._instr.address:08X}: Unsupported immediate usage")
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        imm = imm_op.imm

        if settings.cImmediateParam.checked:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        rm_op = self.locator.locate(OPERAND_MODRM_RM)
        reg_op = self.locator.locate(OPERAND_MODRM_REG)

        if rm_op and rm_op.type == X86_OP_REG and is_stack_reg(rm_op.reg) and settings.cSImmParam.checked:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        if reg_op and is_stack_reg(reg_op.reg) and settings.cSImmParam.checked:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        if rm_op and rm_op.type == X86_OP_REG and is_gp_reg(rm_op.reg) and settings.cGpImmParam.checked:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        if reg_op and is_gp_reg(reg_op.reg) and settings.cGpImmParam.checked:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

        code_refs = list(idautils.CodeRefsTo(imm, 1))
        data_refs = list(idautils.DataRefsTo(imm))

        if code_refs or data_refs:
            if settings.address_parameterization_mode == 0:
                return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * imm_size

            if settings.address_parameterization_mode == 1:
                return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (imm_size - 1) + f"{imm_data[-1]:02X}"

            if settings.address_parameterization_mode == 2:
                return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (imm_size - 2) + f"{imm_data[-2]:02X}" + \
                       f"{imm_data[-1]:02X}"

        return hexlify(self._instr.bytes[imm_offset: imm_offset + imm_size]).decode('utf-8').upper()
