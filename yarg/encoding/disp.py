from dataclasses import dataclass


from ..utils import SettingsDialog, generate_8bit_pattern_2_0_any, \
    generate_8bit_pattern_5_0_any, generate_8bit_pattern_5_3_any, TEMPLATE_SYMBOL

from .modrm import ModRm
from .sib import Sib


@dataclass
class Displacement:
    disp: int
    offset: int
    size: int
    data: bytes

    modrm: ModRm
    sib: Sib

    @classmethod
    def from_instr(cls, instr, modrm: ModRm, sib: Sib) -> 'Displacement':
        data = instr.bytes[instr.disp_offset: instr.disp_offset + instr.disp_size]
        return cls(disp=instr.disp, modrm=modrm, sib=sib, offset=instr.disp_offset, size=instr.disp_size, data=data)

    def print(self):
        print(f"Disp: {self.disp: 08X}")
        print(f"Disp off: {self.offset: 02X}")
        print(f"Disp size: {self.size: 02X}")

    def parameterize_address(self, settings: SettingsDialog):
        if settings.address_parameterization_mode == 0:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * self.size

        if settings.address_parameterization_mode == 1:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (self.size - 1) + f"{self.data[-1]:02X}"

        if settings.address_parameterization_mode == 2:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (self.size - 2) + f"{self.data[-2]:02X}" + \
                   f"{self.data[-1]:02X}"

    def parameterize_offset(self, settings):
        if settings.offset_parameterization_mode == 0:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * self.size

        if settings.offset_parameterization_mode == 1:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (self.size - 1) + f"{self.data[-1]:02X}"

        if settings.offset_parameterization_mode == 2:
            return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * (self.size - 2) + f"{self.data[-2]:02X}" + \
                   f"{self.data[-1]:02X}"

    def parameterize_default(self, settings: SettingsDialog):
        return f"{TEMPLATE_SYMBOL}{TEMPLATE_SYMBOL}" * self.size