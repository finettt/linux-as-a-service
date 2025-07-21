import yaml
from typing import Optional, Dict, Any


class CfgLoader:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.config: Dict[str, Any] = None

    def load_config(self) -> None:
        try:
            with open(self.file_path, "r") as file:
                self.config = yaml.safe_load(file)
        except FileNotFoundError:
            raise FileNotFoundError(f"The file {self.file_path} was not found.")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML file: {e}")

    def get(self, key: str) -> Optional[Any]:
        return self.config.get(key)

    def set(self, key: str, value: Any) -> None:
        if not isinstance(value, (str, int, float, bool, list, dict)):
            raise TypeError("Value must be a string, int, float, bool, list, or dict.")
        self.config[key] = value
        print(f"Configured {key} to {value}")

    def __str__(self):
        return yaml.dump(self.config, default_flow_style=False)
