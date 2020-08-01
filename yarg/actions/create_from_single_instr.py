import idaapi
import ida_bytes
import ida_kernwin as kw

from capstone import *

from ..utils import get_bitness, SettingsDialog, __ver_major__, __ver_minor__, VAR_NAME
from ..builder import create_pattern_from_code


class CreatePatternFromSelectedInstructionHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = kw.get_screen_ea()
        if not ea:
            print("[~] [YarG] [CreatePatternFromSelectedInstructionHandler] Selected instruction is invalid !")
            return

        size = idaapi.get_item_size(ea)
        code = ida_bytes.get_bytes(ea, size)

        if not code:
            print(f"[~] [YarG] [CreatePatternFromSelectedInstructionHandler] "
                  f"Selected instruction is invalid. Reading failed (S:{hex(ea)} ; E:{hex(ea + size)}) !")

        bitness = get_bitness()
        if bitness == 16:
            print("[~] [YarG] [CreatePatternFromSelectedInstructionHandler] 16-bit mode is unsupported !")
            return

        md = Cs(CS_ARCH_X86, CS_MODE_32 if get_bitness() == 32 else CS_MODE_64)
        md.detail = True

        settings = SettingsDialog(version=f"{__ver_major__}.{__ver_minor__}")
        settings.Compile()

        settings.set_default_check_box_values()

        ok = settings.Execute()
        if not ok:
            return

        pattern = create_pattern_from_code(md, code, ea, settings)

        if settings.cStripWildCards.checked:
            while pattern[-2:] == '??':
                pattern = pattern[:-2]

        yar_var = f"${VAR_NAME}{ea:08X} = {{{pattern}}}"

        kw.ask_text(0, yar_var, "Created pattern")

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_WIDGET

        return idaapi.AST_DISABLE_FOR_WIDGET
