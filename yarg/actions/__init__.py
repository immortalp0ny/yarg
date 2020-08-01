from typing import List, Type, Optional

import idaapi


from .create_from_selection import CreatePatternFromSelectedCodeHandler
from .create_from_function import CreatePatternFromFunctionHandler
from .create_from_single_instr import CreatePatternFromSelectedInstructionHandler
from .create_from_single_basic_block import CreatePatternFromSelectedBasicBlockHandler


class Hooks(idaapi.UI_Hooks):
    def populating_widget_popup(self, widget, popup, ctx):
        if idaapi.get_widget_type(widget) in (idaapi.BWN_DISASM, idaapi.BWN_DISASM_ARROWS):
            action: idaapi.action_desc_t = actions_manager.get(ACTION_CreatePatternFromSelectedCodeHandler)
            idaapi.attach_action_to_popup(widget, popup, action.name, "YarG for Yara/")

            action: idaapi.action_desc_t = actions_manager.get(ACTION_CreatePatternFromFunctionHandler)
            idaapi.attach_action_to_popup(widget, popup, action.name, "YarG for Yara/")

            action: idaapi.action_desc_t = actions_manager.get(ACTION_CreatePatternFromSelectedInstructionHandler)
            idaapi.attach_action_to_popup(widget, popup, action.name, "YarG for Yara/")

            action: idaapi.action_desc_t = actions_manager.get(ACTION_CreatePatternFromSelectedBasicBlockHandler)
            idaapi.attach_action_to_popup(widget, popup, action.name, "YarG for Yara/")

class ActionsManager:
    def __init__(self):
        self._actions: List[idaapi.action_desc_t] = []

    def register(self, handler: Type[idaapi.action_handler_t], text, shortcut=None, tooltip=None, ico_path=None) -> int:
        """
        Register custom action in IDA
        :param handler: Implementation of the 'action_handler_t' type
        :param text: Description of the action
        :param shortcut: Optional: A string containing shortcut for the action
        :param tooltip: Optional: Tooltip for the action
        :param ico_path: Optional: Icon for the action
        :return: Index (int) of the registered action
        """
        ico = -1
        if ico_path:
            ico = idaapi.load_custom_icon(ico_path)

        action_desc = idaapi.action_desc_t(f"YargForYara:{handler.__name__}", text, handler(), shortcut, tooltip, ico)

        self._actions.append(action_desc)

        idaapi.register_action(action_desc)

        return len(self._actions) - 1

    def unregister(self, index: int) -> bool:
        """
        Unregister action in IDA
        :param index: Index of the registered action
        :return: Flag (True or False)
        """
        if 0 >= index or index >= len(self._actions):
            return False

        action_desc = self._actions[index]

        idaapi.unregister_action(action_desc.name)

        return True

    def get(self, index: int) -> Optional[idaapi.action_desc_t]:
        """
        Return registered action by the index
        :param index: Index (int)
        :return: Instance of the registered action
        """
        if 0 > index or index >= len(self._actions):
            return None

        return self._actions[index]


actions_manager = ActionsManager()
ACTION_CreatePatternFromSelectedCodeHandler = actions_manager.register(CreatePatternFromSelectedCodeHandler,
                                                                       "Create code pattern from selected range",
                                                                       shortcut="Ctrl+Alt+R")
ACTION_CreatePatternFromFunctionHandler = actions_manager.register(CreatePatternFromFunctionHandler,
                                                                   "Create code pattern from selected function",
                                                                   shortcut="Ctrl+Alt+F")
ACTION_CreatePatternFromSelectedInstructionHandler = \
    actions_manager.register(CreatePatternFromSelectedInstructionHandler,
                             "Create code pattern from selected instruction",
                             shortcut="Ctrl+Alt+I")

ACTION_CreatePatternFromSelectedBasicBlockHandler = \
    actions_manager.register(CreatePatternFromSelectedBasicBlockHandler,
                             "Create code pattern from selected basic block",
                             shortcut="Ctrl+Alt+B")
