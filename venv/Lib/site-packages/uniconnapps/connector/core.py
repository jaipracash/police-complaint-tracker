from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from . import utils

import grpc
import jwt
import datetime
import signal
import logging
import time
import sys
from concurrent.futures import ThreadPoolExecutor
import importlib

class BaseUcaClient(object):
  def __init__(self, connector_endpoint, app_id, client_id, client_secret,
    use_default_logging=True, use_local_channel=False, capture_exception_traces=True):
    if use_default_logging:
      utils.use_default_logging()

    self.connector_endpoint = connector_endpoint
    self.app_id = app_id
    self.client_id = client_id
    self.client_secret = client_secret

    self.use_local_channel = use_local_channel #Not for production
    self.capture_exception_traces = capture_exception_traces

    self.__shutting_down = False
    self._start_handlers = []
    self._stop_handlers = []
    self.__running_as_daemon = False

  def _get_channel(self):
    if self.use_local_channel:
      credentials = grpc.local_channel_credentials()
    else:
      credentials = grpc.ssl_channel_credentials()
    call_credentials = grpc.metadata_call_credentials(
      lambda context, callback: callback((("x-uca-auth-jwt-token", jwt.encode(
        {"app_id": self.app_id,
         "client_id": self.client_id,
         "iat": datetime.datetime.now(tz=datetime.timezone.utc),
         "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(seconds=30),
         "nbf": datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(seconds=10)
         },
        self.client_secret,
        algorithm="HS256")),), None))
    composite_credentials = grpc.composite_channel_credentials(credentials, call_credentials)

    connector_endpoint = self.connector_endpoint

    if connector_endpoint.startswith("uca://"):
      connector_endpoint = connector_endpoint.partition("uca://")[2]

    if ":" not in connector_endpoint:
      if self.use_local_channel:
        connector_endpoint = connector_endpoint+":9800"
      else:
        connector_endpoint = connector_endpoint+":9843"
    
    return grpc.secure_channel(connector_endpoint, composite_credentials)

  def __init_signals(self):
    #refer https://github.com/turnbullerin/graceful-shutdown/blob/fb6180bd2a00083567059bbf4044bd3545bbdb85/src/graceful_shutdown/manager.py#L94
    signal.signal(signal.SIGINT, self.__handle_quit)
    signal.signal(signal.SIGTERM, self.__handle_exit)
    if hasattr(signal, "SIGQUIT"):
      signal.signal(signal.SIGQUIT, self.__handle_quit)
    if hasattr(signal, "SIGHUP"):
      signal.signal(signal.SIGHUP, self.__handle_quit)
    if hasattr(signal, "SIGBREAK"):
      signal.signal(signal.SIGBREAK, self.__handle_quit)
    if hasattr(signal, "SIGABRT"):
      signal.signal(signal.SIGABRT, self.__handle_quit)

    if importlib.util.find_spec("win32api"):
      import win32api
      win32api.SetConsoleCtrlHandler(self.__handle_win32_event, True)

  def __handle_win32_event(self, sig):
    import win32con
    if sig in (win32con.CTRL_CLOSE_EVENT, win32con.CTRL_SHUTDOWN_EVENT, win32con.CTRL_LOGOFF_EVENT):
      self.__handle_quit(sig, None)
      return True
    else:
      return False


  def __handle_exit(self, sig, frame):
    self.stop()

  def __handle_quit(self, sig, frame):
    self.stop()
    if not self.__running_as_daemon:
      time.sleep(1)
      sys.exit(0)

  def start(self):
    logging.info("Starting Uniconnapp.")
    for each_handler in self._start_handlers:
      each_handler()

  def stop(self):
    if not self.__shutting_down:
      self.__shutting_down = True
      logging.info("Gracefully Shutting Down Uniconnapp.")
      for each_handler in self._stop_handlers:
        each_handler()
      logging.info("Gracefull Shutting Down Completed.")

  def run_forever(self):
    self.__init_signals()
    self.start()
    if hasattr(signal, "pause"):
      signal.pause()
    else:#for windows
      try:
        sys.stdin.read()
      except KeyboardInterrupt:
        pass

    self.stop()

  def run_as_daemon(self):
    if self.__running_as_daemon:
      logging.error("Alredy running as daemon.")
      return
    self.__init_signals()
    self.__running_as_daemon = True
    self.start()

  @classmethod
  def auto_load_modules(cls, path="."):
    utils.auto_load_modules(path)
    