from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from uniconnapps.connector_proto.actions.v1 import main_pb2 as actions_pb2
from uniconnapps.connector_proto.actions.v1 import main_pb2_grpc as actions_pb2_grpc

from uniconnapps.connector_proto.common import messages_pb2

from google.protobuf.json_format import Parse, ParseDict, MessageToDict, ParseError
import logging
import threading
import time
from . import utils
import traceback
import datetime
from google.protobuf.timestamp_pb2 import Timestamp

import grpc

import inspect

class ActionsWorker(threading.Thread):
  def __init__(self, stub, registry, type_regex=None, tenant_id_regex=None, capture_exception_traces=False):
    threading.Thread.__init__(self)

    self.__stub = stub
    self.__registry = registry
    self.type_regex = type_regex or ".*"
    self.tenant_id_regex = tenant_id_regex or ".*"
    self.capture_exception_traces = capture_exception_traces
    self.__shutting_down = False
    self.__shut_down_completed = False
    self.__message_pb = None

  def shut_down(self):
    self.__shutting_down = True


  def __actions_request_gen(self):
    if self.__message_pb is None:
      message_pb = ParseDict({
          "type_regex": self.type_regex,
          "tenant_id_regex": self.tenant_id_regex
          },
          actions_pb2.StreamActionsRequest()
          )
    else:
      message_pb = self.__message_pb
      self.__message_pb = None
    if message_pb.action_result.action_id:
      logging.info("Sending action_result {} and requesting next action".format(
        message_pb.action_result.action_id))
    else:
      logging.debug("No Pending action_result and Requesting next action")
    if self.__shutting_down:
      message_pb.worker_status = actions_pb2.StreamActionsRequest.TERMINATING
      yield message_pb
      self.__shut_down_completed = True
    else:
      message_pb.worker_status = actions_pb2.StreamActionsRequest.NORMAL
      yield message_pb

  def run(self):
    action_result = None
    while not self.__shut_down_completed:
      try:
        self.__run_one_cycle()
      except Exception as err:
        logging.exception(err)
        logging.info("Exception in retriving actions, retrying")
        time.sleep(1)

  def __run_one_cycle(self):
    logging.info("Streaming Actions from UCA Cloud Queue...")
    for action_stream_res in self.__stub.streamActions(
        self.__actions_request_gen()):
      if action_stream_res.action.id:
        action = action_stream_res.action
        logging.debug("action request received: {}".format(MessageToDict(action)))
        action_result = self.__execute_action(
          action_id=action_stream_res.action.id,
          type_key=action.type,
          tenant_id=action.tenant_id,
          parameters=action.parameters)
        message_pb = ParseDict({
          "type_regex": self.type_regex,
          "tenant_id_regex": self.tenant_id_regex,
          "action_result": {
            "action_id": action_result["action_id"],
            "result": action_result["result"],
            "errors": action_result["errors"]
            }
          },
          actions_pb2.StreamActionsRequest()
        )
        message_pb.action_result.execution_start_timestamp.FromDatetime(action_result["execution_start_timestamp"])
        message_pb.action_result.execution_end_timestamp.FromDatetime(action_result["execution_end_timestamp"])
        self.__message_pb = message_pb

      else:
        self.__message_pb = None

  def __execute_action(self,action_id, type_key, tenant_id, parameters):
    errors = []
    action_type = self.__registry.get(type_key)
    execution_start_timestamp = None
    execution_end_timestamp = None
    return_value = None
    result = None
    if not action_type:
      errors.append("{} not in actions registry".format(type_key))
      execution_start_timestamp = execution_end_timestamp = datetime.datetime.utcnow()

    else:
      args,kwargs = utils.parameters_to_python(parameters, action_type["parameters_schema"])
      try:
        execution_start_timestamp = datetime.datetime.utcnow()
        return_value = action_type["function"](*args,**kwargs)
        execution_end_timestamp = datetime.datetime.utcnow()
      except Exception as e:
        execution_end_timestamp = datetime.datetime.utcnow()
        logging.exception(e)
        errors.append("Exception occurred in action implementation")
        if self.capture_exception_traces:
          errors.append(traceback.format_exc())

      if return_value is not None and action_type.get("result_schema"):
        try:
          result = utils.python_to_parameters(return_value, action_type["result_schema"])
        except Exception as e:
          logging.exception(e)
          errors.append("Invalid return value or result not compatible with schema")
        if result is not None:
          try:
            ParseDict(result,
            messages_pb2.NestedAttributes()
            )
          except ParseError as e:
            result = None
            logging.exception(e)
            errors.append("Invalid return value, result Value may be out of range")
          except Exception as e:
            result = None
            logging.exception(e)
            errors.append("Error processing return value")

    return {
        "action_id": action_id,
        "result": result,
        "errors": errors,
        "execution_start_timestamp": execution_start_timestamp,
        "execution_end_timestamp": execution_end_timestamp
        }


class ActionsMixin(object):
  def __init__(self):
    self.__ACTIONS_STUB = None
    self.__REGISTRY = {}
    self._start_handlers.append(self._start_handler)
    self._stop_handlers.append(self._stop_handler)
    self.__workers = []

  def _get_actions_stub(self):
    if self.__ACTIONS_STUB is None:
      self.__ACTIONS_STUB = actions_pb2_grpc.ActionsServiceStub(self._get_channel())
    return self.__ACTIONS_STUB

  def _push_action_type(self, key, description=None, parameters_schema=None, result_schema=None):
    if description is None:
      description = key
    action_schema_request_pb = ParseDict({
      "action_type":{
        "key": key,
        "description": description,
        "parameters_schema": parameters_schema,
        "result_schema": result_schema
          }
        },
      actions_pb2.PushActionTypeRequest()
      )
    res = self._get_actions_stub().pushActionType(action_schema_request_pb)
    res_dict = MessageToDict(res,preserving_proto_field_name=True)
    logging.info("push_action_type res: {}".format(res_dict))
    return res_dict

  def _start_handler(self):
    worker = ActionsWorker(stub=self._get_actions_stub(),registry=self.__REGISTRY, capture_exception_traces=self.capture_exception_traces)
    self.__workers.append(worker)
    worker.start()
  def _stop_handler(self):
    for each in self.__workers:
      each.shut_down()
    for each in self.__workers:
      each.join()

  def _push_action_type(self, key, parameters_schema=None, result_schema=None):
    action_schema_request_pb = ParseDict({
      "action_type":{
        "key": key,
        "parameters_schema": parameters_schema,
        "result_schema": result_schema
        }
        },
      actions_pb2.PushActionTypeRequest()
      )
    res = self._get_actions_stub().pushActionType(action_schema_request_pb)
    res_dict = MessageToDict(res,preserving_proto_field_name=True)
    logging.debug("push_action_type res: {}".format(res_dict))
    return res_dict

  def register_action_type(self, key=None, function=None, allow_overriding=False):
    if function is None:
      raise ValueError("function is required")
    function_name = function.__name__
    function_module = inspect.getmodule(function)
    if function_module:
      function_module_name = function_module.__name__
      function_module_package = function_module.__package__
    else:
      function_module_name = ""
      function_module_package = ""
    logging.info("Registering {style}{function_name}{end_style} from {style}{function_module_name}{end_style} as {style}{key}{end_style}".format(
      function_name=function_name, function_module_name=function_module_name,
      key=key,
      style=utils.TerminalStyles.GREEN, end_style=utils.TerminalStyles.END))

    registered_action_type = self.__REGISTRY.get(key)
    if registered_action_type and registered_action_type["function"] != function:
      if allow_overriding:
        logging.warn("overriding action old={} new={}".format(registered_action_type["function"], function))
      else:
        raise ValueError("conflicting action types {} {} for key {}.".format(
          registered_action_type["function"],function, key)
        )

    parameters_schema = utils.detect_function_parameters_schema(function)
    result_schema = utils.detect_function_result_schema(function)
    push_action_type_res = self._push_action_type(key, parameters_schema=parameters_schema, result_schema=result_schema)

    if push_action_type_res.get("change_reject_reasons"):
      raise ValueError("Action Type not accepted: {}".format(push_action_type_res.get("change_reject_reasons")))

    action_type = push_action_type_res["action_type"]
    action_type["function"] = function
    self.__REGISTRY[key] = action_type

  def action(self, *args, type=None, allow_overriding=False):
    def decorator(function):
      nonlocal type
      nonlocal allow_overriding
      if not type:
        type = function.__name__
      self.register_action_type(key=type, function=function, allow_overriding=allow_overriding)

      def wrapper(*args, **kwargs):
        result = function(*args, **kwargs)
        return result

      return wrapper

    if len(args) ==1 and callable(args[0]):
      #No arguments, this is the decorator, @action
      return decorator(args[0])
    else:
      #arguments, this is the decorator, @action() or @action(type="test")
      return decorator
