from dataclasses import dataclass


from ..utils import SettingsDialog, generate_8bit_pattern_2_0_any, \
    generate_8bit_pattern_5_0_any, generate_8bit_pattern_5_3_any, dbg_print


@dataclass
class ModRm:
    mod: int
    reg: int
    rm: int
    reg_ext: int
    rm_ext: int

    @classmethod
    def from_instr(cls, instr, reg_ext, rm_ext) -> 'ModRm':
        return cls(mod=instr.modrm >> 6, reg=(instr.modrm & 0x38) >> 3,
                   rm=instr.modrm & 7, reg_ext=reg_ext, rm_ext=rm_ext)

    @property
    def reg_id(self):
        return (self.reg_ext << 3) | self.reg

    @property
    def rm_id(self):
        return (self.rm_ext << 3) | self.rm

    @property
    def value(self):
        return (self.mod << 6) | (self.reg << 3) | self.rm

    def print(self):
        print(f"ModRm : {self.value:02X}")
        print(f"Mod   : {self.mod:02b}")
        print(f"Reg   : {self.reg_ext:01b}.{self.reg:03b}")
        print(f"Rm:   : {self.rm_ext:01b}.{self.rm:03b}")

    def is_mem_rip_rel(self):
        return self.mod == 0 and self.rm_id in (5, 13)

    def is_mem_with_sib(self):
        return self.rm_id in (4, 12) and self.mod != 3  # rm == 0.100 or rm == 1.100 (sp, r12)

    def is_mem_with_sib_only(self):
        return self.mod == 0 and self.is_mem_with_sib()

    def is_mem_with_sib_and_disp(self):
        return self.is_mem_with_sib_and_disp_8() or self.is_mem_with_sib_and_disp_32()

    def is_mem_with_sib_and_disp_8(self):
        return self.mod == 1 and self.is_mem_with_sib()

    def is_mem_with_sib_and_disp_32(self):
        return self.mod == 2 and self.is_mem_with_sib()

    def is_mem_with_rm_base_reg(self):
        return self.rm_id not in (4, 12) and self.mod != 3

    def is_mem_with_rm_base_reg_and_disp(self):
        return self.is_mem_with_rm_base_reg_and_disp_8() or self.is_mem_with_rm_base_reg_and_disp_32()

    def is_mem_with_rm_base_reg_and_disp_8(self):
        return self.mod == 1 and self.is_mem_with_rm_base_reg()

    def is_mem_with_rm_base_reg_and_disp_32(self):
        return self.mod == 2 and self.is_mem_with_rm_base_reg()

    def is_only_reg(self):
        return self.mod == 3

    def is_only_mem_reg(self):
        return self.mod == 0 and self.rm_id not in (5, 13, 4, 12)

    def parameterize(self, rotate_reg, rotate_rm, settings: SettingsDialog):
        assert 0 <= rotate_reg <= 1 and 0 <= rotate_rm <= 1

        generators = [[self._gen_cst_mode_reg_rm_pattern, self._gen_cst_mode_reg_pattern],
                      [self._gen_cst_mode_rm, self._gen_cst_mode_pattern]]

        return generators[rotate_reg][rotate_rm](settings)

    def _gen_cst_mode_reg_pattern(self, settings: SettingsDialog):
        dbg_print("_gen_cst_mode_reg_pattern()")
        return generate_8bit_pattern_2_0_any(self.mod, self.reg, settings)

    def _gen_cst_mode_pattern(self, settings: SettingsDialog):
        dbg_print("_gen_cst_mode_pattern()")
        return generate_8bit_pattern_5_0_any(self.mod, settings)

    def _gen_cst_mode_reg_rm_pattern(self, settings: SettingsDialog):
        dbg_print("_gen_cst_mode_reg_rm_pattern()")
        return f"{self.value:02X}"

    def _gen_cst_mode_rm(self, settings: SettingsDialog):
        dbg_print("_gen_cst_mode_rm()")
        return generate_8bit_pattern_5_3_any(self.mod, self.rm, settings)