from dataclasses import dataclass


from ..utils import SettingsDialog, generate_8bit_pattern_2_0_any, \
    generate_8bit_pattern_5_0_any, generate_8bit_pattern_5_3_any, dbg_print


@dataclass
class Sib:
    mod: int
    scale: int
    index: int
    base: int
    index_ext: int
    base_ext: int

    @classmethod
    def from_instr(cls, instr, mod, index_ext, base_ext) -> 'Sib':
        assert (mod != 3)

        return cls(mod=mod, scale=instr.sib >> 6, index=(instr.sib & 0x38) >> 3,
                   base=instr.sib & 7, index_ext=index_ext, base_ext=base_ext)

    @property
    def index_id(self):
        return (self.index_ext << 3) | self.index

    @property
    def base_id(self):
        return (self.base_ext << 3) | self.base

    @property
    def value(self):
        return (self.scale << 6) | (self.index << 3) | self.base

    def print(self):
        print(f"Sib   : {self.value:02X}")
        print(f"Scale : {self.scale:02b}")
        print(f"Index : {self.index_ext:01b}.{self.index:03b}")
        print(f"Base  : {self.base_ext:01b}.{self.base:03b}")

    def is_mem_with_base_reg(self):
        return not self.is_mem_without_base_reg()

    def is_mem_without_base_reg(self):
        return self.mod == 0 and self.base_id in (5, 13)

    def is_mem_with_index(self):
        return self.index_id != 4

    def is_mem_with_only_index_disp_32(self):
        return self.is_mem_with_index() and self.mod == 0 and self.base_id == 5

    def is_mem_without_base_reg_and_with_disp32_index_scale(self):
        return self.is_mem_without_base_reg() and self.index_id != 4

    def is_mem_with_base_only(self):
        return self.mod == 0 and self.base_id not in (5, 13) and self.index_id == 4

    def is_mem_with_base_only_disp(self):
        return self.mod != 0 and self.index_id == 4

    def is_mem_with_base_only_disp8(self):
        return self.mod == 1 and self.is_mem_with_base_only_disp()

    def is_mem_with_base_only_disp32(self):
        return self.mod == 2 and self.is_mem_with_base_only_disp()

    def is_mem_with_base_index_scale_only(self):
        return self.mod == 0 and self.base_id not in (5, 13) and self.is_mem_with_index()

    def is_mem_with_base_index_scale_disp(self):
        return self.is_mem_with_base_index_scale_disp8() or self.is_mem_with_base_index_scale_disp32()

    def is_mem_with_base_index_scale_disp8(self):
        return self.mod == 1 and not self.is_mem_with_base_only_disp()

    def is_mem_with_base_index_scale_disp32(self):
        return self.mod == 2 and not self.is_mem_with_base_only_disp()

    def parameterize(self, rotate_index, rotate_base, settings: SettingsDialog):
        assert 0 <= rotate_index <= 1 and 0 <= rotate_base <= 1

        generators = [[self._gen_cst_scale_index_base_pattern, self._gen_cst_scale_index_pattern],
                      [self._gen_cst_scale_base_pattern, self._gen_cst_scale_pattern]]

        return generators[rotate_index][rotate_base](settings)

    def _gen_cst_scale_pattern(self, settings: SettingsDialog):
        dbg_print("_gen_cst_scale_pattern()")
        return generate_8bit_pattern_5_0_any(self.scale, settings)

    def _gen_cst_scale_index_pattern(self, settings: SettingsDialog):
        dbg_print("_gen_cst_scale_index_pattern()")
        return generate_8bit_pattern_2_0_any(self.scale, self.index, settings)

    def _gen_cst_scale_index_base_pattern(self, settings: SettingsDialog):
        dbg_print("_gen_cst_scale_index_base_pattern()")
        return f"{self.value:02X}"

    def _gen_cst_scale_base_pattern(self, settings: SettingsDialog):
        dbg_print("_gen_cst_scale_base_pattern()")
        return generate_8bit_pattern_5_3_any(self.scale, self.base, settings)
