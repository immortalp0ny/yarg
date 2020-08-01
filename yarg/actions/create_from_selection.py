import idaapi
import ida_bytes
import ida_kernwin as kw

from capstone import *

from ..utils import get_selected_range, get_bitness, SettingsDialog, __ver_major__, __ver_minor__, VAR_NAME
from ..builder import create_pattern_from_code


class CreatePatternFromSelectedCodeHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        start, end = get_selected_range()
        if not start or not end:
            print("[~] [YarG] [CreatePatternFromSelectedCodeHandler] Selected range is invalid !")
            return

        code = ida_bytes.get_bytes(start, end - start)
        if not code:
            print(f"[~] [YarG] [CreatePatternFromSelectedCodeHandler] "
                  f"Selected range is invalid. Reading failed (S:{hex(start)} ; E:{hex(end)}) !")

        bitness = get_bitness()
        if bitness == 16:
            print("[~] [YarG] [CreatePatternFromSelectedCodeHandler] 16-bit mode is unsupported !")
            return

        md = Cs(CS_ARCH_X86, CS_MODE_32 if get_bitness() == 32 else CS_MODE_64)
        md.detail = True

        settings = SettingsDialog(version=f"{__ver_major__}.{__ver_minor__}")
        settings.Compile()

        settings.set_default_check_box_values()

        ok = settings.Execute()
        if not ok:
            return

        pattern = create_pattern_from_code(md, code, start, settings)

        if settings.cStripWildCards.checked:
            while pattern[-2:] == '??':
                pattern = pattern[:-2]

        yar_var = f"${VAR_NAME}{start:08X} = {{{pattern}}}"

        kw.ask_text(0, yar_var, "Created pattern")

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_WIDGET

        return idaapi.AST_DISABLE_FOR_WIDGET
