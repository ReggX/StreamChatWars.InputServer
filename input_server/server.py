'''
VERY UNSAFE implementation of a remote server to handle input commands sent
by clients.

All that protects you from unpickling potentially dangerous user input is a
flimsy whitelist, so beware!

NEVER bind the TCPServer to publicly accessible interfaces, i.e. outside
your trusted LAN environment. Heck, treat your LAN with suspicion too!
'''

# native imports
import json
import pickle
import socketserver
import sys
from base64 import b64decode
from collections.abc import Mapping
from fnmatch import fnmatch
from functools import partial
from io import BytesIO
from socket import socket
from threading import Thread
from time import sleep
from typing import Any

# pip imports
from Cryptodome.Cipher import AES
from Cryptodome.Cipher._mode_gcm import GcmMode
from Cryptodome.Hash import SHA3_256

# local imports
import streamchatwars.virtual_input.gamepads
import streamchatwars.virtual_input.input_server
from streamchatwars._shared.helpers_color import ColorText
from streamchatwars._shared.types import InputServerDataPack

# internal imports
from .config import Server_Settings
from .config import get_server_settings
from .config import read_config


settings: Server_Settings
keep_running: bool = True


def in_whitelist(address: str) -> bool:
  pattern: str
  for pattern in settings.whitelist:
    if fnmatch(address, pattern):
      return True
  return False


def in_blacklist(address: str) -> bool:
  pattern: str
  for pattern in settings.blacklist:
    if fnmatch(address, pattern):
      return True
  return False


class ContinueException(Exception):
  pass


class CustomServer(socketserver.TCPServer):
  key: bytes
  encryption_mode: str | None


class InputServerHandler(socketserver.BaseRequestHandler):
  server: CustomServer

  def verify_data_pack_structure(self, data_pack: InputServerDataPack) -> bool:
    try:
      assert 'type' in data_pack
      assert data_pack["type"] in ('input', )
      assert 'encryption' in data_pack
      assert data_pack["encryption"] in (None, 'AES-GCM', )
      assert 'data' in data_pack
      if data_pack["encryption"]:
        assert 'auth_tag' in data_pack
        assert 'nonce' in data_pack
      return True
    except AssertionError:
      return False

  def unpack_data(self, data_pack: InputServerDataPack) -> bytes:
    '''
    Unpack data from (encrypted) data_pack.
    '''
    # verify structure
    if not self.verify_data_pack_structure(data_pack):
      print(ColorText.error(
        'Invalid data structure! Skipping this package...\n'
        f'{data_pack}'
      ))
      raise ContinueException

    if data_pack["encryption"] or self.server.encryption_mode:
      # package is encrypted

      if data_pack["encryption"] != self.server.encryption_mode:
        # encryption mismatch
        print(ColorText.error(
          f'Invalid encryption mode! Expected {self.server.encryption_mode}, '
          f'got {data_pack["encryption"]} instead! Skipping this package...\n'
          f'{data_pack}'
        ))
        raise ContinueException

      if self.server.encryption_mode == 'AES-GCM':
        # decrypt using AES-GCM
        assert 'nonce' in data_pack  # shut up type checker
        cipher: GcmMode = AES.new(  # type: ignore
          key=self.server.key,
          mode=AES.MODE_GCM,
          nonce=b64decode(data_pack["nonce"])
        )
        cipher.update(data_pack['type'].encode('utf-8'))  # make sure type gets verified
        try:
          unpacked_data = cipher.decrypt_and_verify(
            ciphertext=b64decode(data_pack['data']),
            received_mac_tag=b64decode(data_pack["auth_tag"])
          )
        except ValueError:
          print(ColorText.error(
            'Decryption failed! Skipping this package...\n'
            f'{data_pack}'
          ))
          raise ContinueException
      else:
        raise ValueError(f'Unknown encryption mode: {self.server.encryption_mode}')

    else:
      # no encryption
      unpacked_data = b64decode(data_pack['data'])

    return unpacked_data

  def handle(self) -> None:
    '''
    Handle data receival from remote client.
    '''
    # self.request is the TCP socket connected to the client
    remote_socket: socket = self.request
    remote_socket.settimeout(1.0)  # make socket.recv() non-blocking
    while keep_running:
      # ===== Receive data =====
      try:
        self.data: bytes = remote_socket.recv(16 * 4096)
      except TimeoutError:
        continue

      if in_blacklist(self.client_address[0]):
        print(ColorText.error(f"{self.client_address[0]} in blacklist!"))
        return
      if not in_whitelist(self.client_address[0]):
        print(ColorText.error(f"{self.client_address[0]} not in whitelist!"))
        return
      if self.data == b'':
        return

      # in case recv connected more than one data_pack together, we need to
      # split them up:
      # First 4 bytes are length of the data_pack (big endian)
      with BytesIO(self.data) as data_stream:
        while True:
          # repeat until data_stream is empty
          data_length: int = int.from_bytes(data_stream.read(4), 'big')
          if data_length == 0:
            break
          try:
            data_string: str = data_stream.read(data_length).decode('utf-8')
          except UnicodeDecodeError:
            print(ColorText.warning(
              "Failed to decode received data, skipping..."
            ))
            continue

          if len(data_string) != data_length:
            print(ColorText.warning(
              "Data pack length mismatch detected! "
              f"Header: {data_length}, Actual: {len(data_string)}"
            ))
            continue

          # ===== Decode data =====
          try:
            data_pack: InputServerDataPack = json.loads(data_string)
          except json.JSONDecodeError:
            print(ColorText.error(
              'Received package is not valid JSON! Skipping this package...\n'
              f'{data_string}'
            ))
            continue

          # ===== Unpack data =====
          try:
            unpacked_data = self.unpack_data(data_pack)
          except ContinueException:
            continue

          # ===== Execute data =====
          if data_pack['type'] == 'input':
            try:
              partial_function: partial[Any] = pickle.loads(unpacked_data)
            except pickle.UnpicklingError:
              print(ColorText.error("UnpicklingError"))
              continue

            func_class: Any | None = getattr(partial_function.func, '__self__', None)
            func_class_name: str = getattr(func_class, "__name__", "")
            if func_class_name:
              func_class_name = f"{func_class_name}."

            print(
              f">>{self.client_address[0]}:{self.client_address[1]}: "
              f"{func_class_name}{partial_function.func.__name__}"
              f"(*args={partial_function.args}, **kwargs={partial_function.keywords})"
            )
            partial_function()
          else:
            print(ColorText.error(
              f"Unknown pack type: {data_pack['type']}! Skipping this package..."
            ))
            continue


def start_server(
  port: int,
  encryption_key: str = '',
  encryption_mode: str = 'AES-GCM'
) -> None:
  socketserver.TCPServer.allow_reuse_address = True
  with CustomServer((settings.bind_hostname, port), InputServerHandler) as server:
    server.encryption_mode = None
    server.key = b''
    if encryption_key:
      server.key = SHA3_256.new(encryption_key.encode('utf-8')).digest()
      server.encryption_mode = 'AES-GCM'
    Thread(target=server.serve_forever).start()
    while keep_running:
      sleep(0.1)
    server.shutdown()
    return


def main() -> None:
  global keep_running, settings
  ColorText.init()
  config_file = sys.argv[1] if len(sys.argv) > 1 else 'config/default.json'
  config: Mapping[str, Any] = read_config(filename=config_file)
  settings = get_server_settings(config)
  print(
    f"Creating {len(settings.xinput_gamepads)} XInput gamepads with index "
    f"{', '.join(str(i) for i in settings.xinput_gamepads)}"
  )
  gamepad_server: streamchatwars.virtual_input.input_server.LocalInputServer
  gamepad_server = streamchatwars.virtual_input.input_server.LocalInputServer()
  for i in settings.xinput_gamepads:
    gamepad_server.add_gamepad(i)
  print(
    f"Starting up {len(settings.bind_ports)} "
    f"{'' if settings.encryption_key else 'un'}encrypted "
    f"servers with ports: {', '.join(str(i) for i in settings.bind_ports)}"
  )
  for i in settings.bind_ports:
    kwargs = {
      'port': i,
      'encryption_key': settings.encryption_key,
      'encryption_mode': settings.encryption_mode
    }
    Thread(target=start_server, kwargs=kwargs).start()
  try:
    while True:
      sleep(0.1)
  except KeyboardInterrupt:
    keep_running = False
    print(ColorText.warning("Exiting child threads..."))
    return
