import idaapi
import ida_kernwin as kw

from capstone.x86_const import *


class SettingsDialog(kw.Form):
    def __init__(self, version="0.1", extension=r"", extension_controls={}):
        controls = {'cModeGroup1': idaapi.Form.ChkGroupControl(("cGpRegistersParam", "cSRegistersParam",)),
                    'cModeGroup2': idaapi.Form.RadGroupControl(("cFullAddressParam", "cOneByteAddressParam",
                                                                "cTwoByteAddressParam",), 1),
                    'FormChangeCb': idaapi.Form.FormChangeCb(self.OnFormChange),

                    'cModeGroup4': idaapi.Form.ChkGroupControl(("cFoldSameHigh4bit", "cFoldSameLow4bit",
                                                                "cStripWildCards", "cTrackBasicBlockSequences",)),
                    'cModeGroup3': idaapi.Form.RadGroupControl(("cFullCodeOffsetParam",
                                                                "cOneByteOffsetParam",
                                                                "cTwoByteOffsetParam",), 1),
                    'cModeGroup5': idaapi.Form.ChkGroupControl(("cImmediateParam", "cGpImmParam", "cSImmParam",)),
                    'cModeGroup6': idaapi.Form.ChkGroupControl(("iR8", "iR9", "iR10", "iR11",
                                                                "iR12", "iR13", "iR14", "iR15",)),
                    'cModeGroup7': idaapi.Form.ChkGroupControl(("iAX", "iDX", "iCX", "iBX", "iSI",
                                                                "iDI", "iSP", "iBP",)),
                    'cModeGroup8': idaapi.Form.ChkGroupControl(("iSP", "iBP",)),
                    'cModeGroup9': idaapi.Form.ChkGroupControl(("cSDisplacementParam", "cGpDisplacementParam",))
                    }
        controls.update(extension_controls)

        kw.Form.__init__(self, r"""Code pattern generator for IDA. v""" + version + r"""
                        {FormChangeCb}
                        <##Registers##GP registers parametrisation:{cGpRegistersParam}>
                        <#SP/BP registers parametrisation:{cSRegistersParam}>{cModeGroup1}>
                        <##GP selector##(E/R/H/L)AX:{iAX}><(E/R/H/L)DX:{iDX}>              
                        <(E/R/H/L)CX:{iCX}>
                        <(E/R/H/L)BX:{iBX}>
                        <(E/R/H/L)SI:{iSI}>
                        <(E/R/H/L)DI:{iDI}>{cModeGroup7}>
                        <##GP64 selector##(R/D/W)R8:{iR8}><(R/D/W)R9:{iR9}>
                        <(R/D/W)R10:{iR10}>
                        <(R/D/W)R11:{iR11}>
                        <(R/D/W)R12:{iR12}>
                        <(R/D/W)R13:{iR13}>
                        <(R/D/W)R14:{iR14}>
                        <(R/D/W)R15:{iR15}>{cModeGroup6}>
                        <##SP selector##(E/R/H/L)SP:{iSP}> | <(E/R/H/L)BP:{iBP}>{cModeGroup8}>
                        <##Address##Full address parametrisation:{cFullAddressParam}>
                        <#Parameterize first 3 bytes of address (32bit):{cOneByteAddressParam}>
                        <#Parameterize first 2 bytes of address (32bit):{cTwoByteAddressParam}>{cModeGroup2}>
                        <##Code offset##Full offset parametrisation:{cFullCodeOffsetParam}>
                        <#Parameterize first 3 bytes of offset:{cOneByteOffsetParam}>
                        <#Parameterize first 2 bytes of offset:{cTwoByteOffsetParam}>{cModeGroup3}>
                        <##Pattern optimization##Alternatives with same low 4 bits are folding:{cFoldSameLow4bit}>
                        <#Alternatives with same high 4 bits are folding:{cFoldSameHigh4bit}>
                        <#Strip trailing wildcards:{cStripWildCards}>{cModeGroup4}>
                        <##Immediate value##All constants parametrisation:{cImmediateParam}>
                        <#SP/BP constants parametrisation:{cSImmParam}>
                        <#GP registers constants parametrisation:{cGpImmParam}>{cModeGroup5}>
                        <##Displacement##><#SP/BP displacement parametrisation:{cSDisplacementParam}>
                        <#GP displacement parametrisation:{cGpDisplacementParam}>{cModeGroup9}>
                        """ + extension, controls)

        self.address_parameterization_mode = 1
        self.offset_parameterization_mode = 1
        self.is_gp_enabled = True
        self.is_sp_enabled = False

        self.gp_regs = []
        self.sp_regs = []

        self.gp_chk_regs = []
        self.sp_chk_regs = []

    def OnFormChange(self, fid):
        if fid == -1:
            self.set_default_control_activation()

        elif fid == self.cGpRegistersParam.id:
            self.is_gp_enabled = not self.is_gp_enabled
            self.cGpRegistersParam.checked = self.is_gp_enabled

            self.toogle_gp(self.is_gp_enabled)
            self.check_all_gp(self.is_gp_enabled, update=True)

        elif fid == self.cSRegistersParam.id:
            self.is_sp_enabled = not self.is_sp_enabled
            self.cSRegistersParam.checked = self.is_sp_enabled

            self.toogle_sp(self.is_sp_enabled)
            self.check_all_sp(self.is_sp_enabled, update=True)

        elif fid == self.cSDisplacementParam.id:
            self.cSDisplacementParam.checked = not self.cSDisplacementParam.checked
        elif fid == self.cModeGroup2.id:
            self.address_parameterization_mode = self.GetControlValue(self.cModeGroup2)
        elif fid == self.cModeGroup3.id:
            self.offset_parameterization_mode = self.GetControlValue(self.cModeGroup3)
        elif fid == self.cFoldSameLow4bit.id:
            self.cFoldSameLow4bit.checked = not self.cFoldSameLow4bit.checked
        elif fid == self.cFoldSameHigh4bit.id:
            self.cFoldSameHigh4bit.checked = not self.cFoldSameHig4hbit.checked
        elif fid == self.cImmediateParam.id:
            self.cImmediateParam.checked = not self.cImmediateParam.checked
        elif fid == self.cStripWildCards.id:
            self.cStripWildCards.checked = not self.cStripWildCards.checked
        elif fid == self.cSImmParam.checked:
            self.cSImmParam.checked = not self.cSImmParam.checked
        elif fid == self.cGpImmParam.checked:
            self.cGpImmParam.checked = not self.cGpImmParam.checked
        elif fid == self.iAX.id:
            self.iAX.checked = not self.iAX.checked

            self.fill_gp_collection_by_control_state(self.iAX,
                                                     [X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_EAX, X86_REG_RAX])

        elif fid == self.iDX.id:
            self.iDX.checked = not self.iDX.checked

            self.fill_gp_collection_by_control_state(self.iDX,
                                                     [X86_REG_DH, X86_REG_DL, X86_REG_DX, X86_REG_EDX, X86_REG_RDX])

        elif fid == self.iCX.id:
            self.iCX.checked = not self.iCX.checked

            self.fill_gp_collection_by_control_state(self.iCX,
                                                     [X86_REG_CH, X86_REG_CL, X86_REG_CX, X86_REG_ECX, X86_REG_RCX])

        elif fid == self.iBX.id:
            self.iBX.checked = not self.iBX.checked

            self.fill_gp_collection_by_control_state(self.iBX,
                                                     [X86_REG_BH, X86_REG_BL, X86_REG_BX, X86_REG_EBX, X86_REG_RBX])

        elif fid == self.iSI.id:
            self.iSI.checked = not self.iSI.checked

            self.fill_gp_collection_by_control_state(self.iSI,
                                                     [X86_REG_SIL, X86_REG_SI, X86_REG_ESI, X86_REG_RSI])
        elif fid == self.iDI.id:
            self.iDI.checked = not self.iDI.checked

            self.fill_gp_collection_by_control_state(self.iDI,
                                                     [X86_REG_DIL, X86_REG_EDI, X86_REG_RDI])
        elif fid == self.iSP.id:
            self.iSP.checked = not self.iSP.checked

            self.fill_sp_collection_by_control_state(self.iSP,
                                                     [X86_REG_SPL, X86_REG_SP, X86_REG_ESP, X86_REG_RSP])
        elif fid == self.iBP.id:
            self.iBP.checked = not self.iBP.checked

            self.fill_sp_collection_by_control_state(self.iBP,
                                                     [X86_REG_BPL, X86_REG_BP, X86_REG_EBP, X86_REG_RBP])
        elif fid == self.iR8.id:
            self.iR8.checked = not self.iR8.checked

            self.fill_gp_collection_by_control_state(self.iR8,
                                                     [X86_REG_R8B, X86_REG_R8W, X86_REG_R8D, X86_REG_R8])

        elif fid == self.iR9.id:
            self.iR9.checked = not self.iR9.checked

            self.fill_gp_collection_by_control_state(self.iR9,
                                                     [X86_REG_R9B, X86_REG_R9W, X86_REG_R9D, X86_REG_R9])
        elif fid == self.iR10.id:
            self.iR10.checked = not self.iR10.checked

            self.fill_gp_collection_by_control_state(self.iR10,
                                                     [X86_REG_R10B, X86_REG_R10W, X86_REG_R10D, X86_REG_R10])
        elif fid == self.iR11.id:
            self.iR11.checked = not self.iR11.checked

            self.fill_gp_collection_by_control_state(self.iR11,
                                                     [X86_REG_R11B, X86_REG_R11W, X86_REG_R11D, X86_REG_R11])
        elif fid == self.iR12.id:
            self.iR12.checked = not self.iR12.checked

            self.fill_gp_collection_by_control_state(self.iR12,
                                                     [X86_REG_R12B, X86_REG_R12W, X86_REG_R12D, X86_REG_R12])
        elif fid == self.iR13.id:
            self.iR13.checked = not self.iR13.checked

            self.fill_gp_collection_by_control_state(self.iR13,
                                                     [X86_REG_R13B, X86_REG_R13W, X86_REG_R13D, X86_REG_R13])
        elif fid == self.iR14.id:
            self.iR14.checked = not self.iR14.checked

            self.fill_gp_collection_by_control_state(self.iR14,
                                                     [X86_REG_R14B, X86_REG_R14W, X86_REG_R14D, X86_REG_R14])

        elif fid == self.iR15.id:
            self.iR15.checked = not self.iR15.checked

            self.fill_gp_collection_by_control_state(self.iR15,
                                                     [X86_REG_R15B, X86_REG_R15W, X86_REG_R15D, X86_REG_R15])

        return 1

    def set_default_control_activation(self):
        self.gp_chk_regs = [self.iAX, self.iDX, self.iCX, self.iBX, self.iSI, self.iDI, self.iR8, self.iR9, self.iR10,
                            self.iR11, self.iR12, self.iR13, self.iR14, self.iR15]
        self.sp_chk_regs = [self.iSP, self.iBP]

        self.toogle_gp(self.is_gp_enabled)
        self.toogle_sp(self.is_sp_enabled)

    def set_default_check_box_values(self):
        self.gp_chk_regs = [self.iAX, self.iDX, self.iCX, self.iBX, self.iSI, self.iDI, self.iR8, self.iR9, self.iR10,
                            self.iR11, self.iR12, self.iR13, self.iR14, self.iR15]
        self.sp_chk_regs = [self.iSP, self.iBP]

        self.cGpRegistersParam.checked = self.is_gp_enabled
        self.cSRegistersParam.checked = self.is_sp_enabled

        self.cFoldSameHigh4bit.checked = True
        self.cFoldSameLow4bit.checked = True
        self.cSImmParam.checked = True
        self.cStripWildCards.checked = True
        self.cSDisplacementParam.checked = True

        self.check_all_gp(self.is_gp_enabled)
        self.check_all_sp(self.is_sp_enabled)

    def toogle_gp(self, status):
        for control in self.gp_chk_regs:
            self.EnableField(control, status)

    def toogle_sp(self, status):
        for control in self.sp_chk_regs:
            self.EnableField(control, status)

    def check_all_gp(self, state, update=False):
        for control in self.gp_chk_regs:
            control.checked = state

            if update:
                self.RefreshField(control)
                self.SetControlValue(control, state)

        all_gp = [X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_EAX, X86_REG_RAX, X86_REG_DH, X86_REG_DL, X86_REG_DX,
                  X86_REG_EDX, X86_REG_RDX, X86_REG_CH, X86_REG_CL, X86_REG_CX, X86_REG_ECX, X86_REG_RCX,
                  X86_REG_BH, X86_REG_BL, X86_REG_BX, X86_REG_EBX, X86_REG_RBX, X86_REG_SIL, X86_REG_SI,
                  X86_REG_ESI, X86_REG_RSI, X86_REG_DIL, X86_REG_EDI, X86_REG_RDI, X86_REG_R8B,
                  X86_REG_R8W, X86_REG_R8D, X86_REG_R8, X86_REG_R9B, X86_REG_R9W, X86_REG_R9D, X86_REG_R9,
                  X86_REG_R10B, X86_REG_R10W, X86_REG_R10D, X86_REG_R10, X86_REG_R11B, X86_REG_R11W, X86_REG_R11D,
                  X86_REG_R11, X86_REG_R12B, X86_REG_R12W, X86_REG_R12D, X86_REG_R12, X86_REG_R13B, X86_REG_R13W,
                  X86_REG_R13D, X86_REG_R13, X86_REG_R14B, X86_REG_R14W, X86_REG_R14D, X86_REG_R14, X86_REG_R15B,
                  X86_REG_R15W, X86_REG_R15D, X86_REG_R15]

        if state:
            self.gp_regs.extend(all_gp)
        else:
            self.gp_regs = [x for x in self.gp_regs if x not in all_gp]

    def check_all_sp(self, state, update=False):
        for control in self.sp_chk_regs:
            control.checked = state

            if update:
                self.RefreshField(control)
                self.SetControlValue(control, state)

        all_sp = [X86_REG_SPL, X86_REG_SP, X86_REG_ESP, X86_REG_RSP, X86_REG_BPL, X86_REG_BP, X86_REG_EBP, X86_REG_RBP]

        if state:
            self.sp_regs.extend(all_sp)
        else:
            self.sp_regs = [x for x in self.sp_regs if x not in all_sp]

    def fill_gp_collection_by_control_state(self, control, regs):
        if control.checked:
            self.gp_regs.extend(regs)
        else:
            self.gp_regs = [x for x in self.gp_regs if x not in regs]

    def fill_sp_collection_by_control_state(self, control, regs):
        if control.checked:
            self.sp_regs.extend(regs)
        else:
            self.sp_regs = [x for x in self.sp_regs if x not in regs]
