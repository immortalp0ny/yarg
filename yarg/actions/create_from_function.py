import idaapi
import ida_gdl
import ida_funcs
import ida_bytes
import ida_kernwin as kw

from capstone import *
from plyara.utils import rebuild_yara_rule

from ..utils import get_bitness, SettingsDialog, __ver_major__, __ver_minor__, VAR_NAME
from ..builder import create_pattern_from_code


class CreatePatternFromFunctionHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = kw.get_screen_ea()

        func = ida_funcs.get_func(ea)
        if not func:
            print("[~] [YarG] [CreatePatternFromFunctionHandler] Selected EA doesn't belongs any function !")
            return

        bitness = get_bitness()
        if bitness == 16:
            print("[~] [YarG] [CreatePatternFromFunctionHandler] 16-bit mode is unsupported !")
            return

        md = Cs(CS_ARCH_X86, CS_MODE_32 if get_bitness() == 32 else CS_MODE_64)
        md.detail = True

        settings = SettingsDialog(version=f"{__ver_major__}.{__ver_minor__}")
        settings.Compile()

        settings.set_default_check_box_values()

        ok = settings.Execute()
        if not ok:
            return

        yar_vars = []
        yar_cond = []

        for block in ida_gdl.FlowChart(func):
            code = ida_bytes.get_bytes(block.start_ea, block.end_ea - block.start_ea)

            if not code:
                print(f"[~] [YarG] Block range is invalid. "
                      f"Reading failed (S:{hex(block.start_ea)} ; E:{hex(block.end_ea)}) !")

                return

            pattern = create_pattern_from_code(md, code, block.start_ea, settings)
            if settings.cStripWildCards.checked:
                while pattern[-2:] == '??':
                    pattern = pattern[:-2]

            pattern_address = f"{block.start_ea:016X}" if bitness == 64 else f"{block.start_ea:08X}"

            yar_var = {'name': f"${VAR_NAME}{pattern_address}",
                       'type': 'bytes', 'value': f"{{{pattern}}}"}

            yar_vars.append(yar_var)

        h = (len(yar_vars) // 2) + 1
        yar_cond.extend([f'{h + h//2}', 'of', f'(${VAR_NAME}*)'])

        rule_address = f"{ea:016X}" if bitness == 64 else f"{ea:08X}"

        rule = {'rule_name': f'generate_rule_fn_{rule_address}', 'strings': yar_vars, 'condition_terms': yar_cond}

        yar_rule = rebuild_yara_rule(rule)

        kw.ask_text(0, yar_rule, "Created pattern")

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_WIDGET

        return idaapi.AST_DISABLE_FOR_WIDGET
