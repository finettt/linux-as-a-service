from typing import Dict, List


class History():
    required_keys = {'command', 'output'}
    def __init__(self, history: List[Dict[str,str]]):
        self.__history = history or []
        assert all(
            isinstance(item, dict) and History.required_keys.issubset(item.keys()) for item in history
        ), f"Each element must be a dict containing the keys: {History.required_keys}"

    def add(self, command: Dict[str,str]):
        assert "command" in command.keys() and "output" in command.keys(), f"Bad command format: {command}, expected: {{'command':'...','output':'...'}}"
        self.__history.append(command)
    def get_history(self):
        return self.__history