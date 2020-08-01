import idaapi

from yarg.utils import __ver_minor__, __ver_major__
from yarg.actions import Hooks

hooks = Hooks()
hooks.hook()


class YaraBuilder(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    help = f"YarG for Yara v{__ver_major__}.{__ver_minor__}. Create yara rules/patterns from code"
    wanted_name = f"YarG for Yara"
    wanted_hotkey = ""
    comment = ""

    @staticmethod
    def init():
        return idaapi.PLUGIN_KEEP

    @staticmethod
    def term():
        pass

    @staticmethod
    def run(*args):
        pass


def PLUGIN_ENTRY():
    return YaraBuilder()
