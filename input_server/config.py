
# native imports
import json
from collections.abc import Mapping
from dataclasses import dataclass
from socket import gethostname
from typing import Any


def read_config(filename: str = "config/default.json") -> Mapping[str, Any]:
  with open(filename, mode='r') as config_file:
    return json.load(config_file)


@dataclass
class Server_Settings:
  bind_hostname: str
  bind_ports: list[int]
  encryption_key: str
  encryption_mode: str
  whitelist: list[str]
  blacklist: list[str]
  xinput_gamepads: list[int]


def get_server_settings(config: Mapping[str, Any]) -> Server_Settings:
  bind_hostname: str = config.get('bind_hostname', gethostname())
  bind_ports: list[int] = config.get('bind_ports', [33000, 33001, 33002, 33003, 33004])
  encryption_key: str = config.get('encryption_key', '')
  encryption_mode: str = config.get('encryption_mode', 'AES-GCM')
  whitelist: list[str] = config.get('whitelist', ["127.*", "localhost", "192.168.*"])
  blacklist: list[str] = config.get('blacklist', [])
  xinput_gamepads: list[int] = config.get('xinput_gamepads', [])

  return Server_Settings(
    bind_hostname=bind_hostname,
    bind_ports=bind_ports,
    encryption_key=encryption_key,
    encryption_mode=encryption_mode,
    whitelist=whitelist,
    blacklist=blacklist,
    xinput_gamepads=xinput_gamepads
  )
