from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import uuid
import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.json_format import Parse, ParseDict, MessageToDict
from uniconnapps.connector_proto.events.v1 import main_pb2 as events_pb2
from uniconnapps.connector_proto.events.v1 import main_pb2_grpc as events_pb2_grpc
from . import utils
import logging
import copy


class EventsMixin(object):
  def __init__(self):
    self.__EVENTS_STUB = None
    self.__REGISTRY = {}

  def _get_events_stub(self):
    if self.__EVENTS_STUB is None:
      self.__EVENTS_STUB = events_pb2_grpc.EventsServiceStub(self._get_channel())
    return self.__EVENTS_STUB

  def _push_event_type(self, key, schema=None):
    event_schema_request_pb = ParseDict({
      "event_type":{
        "key": key,
        "schema": schema
          }
        },
      events_pb2.PushEventTypeRequest()
      )
    res = self._get_events_stub().pushEventType(event_schema_request_pb)
    res_dict = MessageToDict(res,preserving_proto_field_name=True)
    logging.debug("push_event_type res: {}".format(res_dict))
    return res_dict

  def register_event_type(self, key, partial_schema=None, sample_properties=None):
    if partial_schema is None:
      partial_schema = {}

    if sample_properties is None:
      sample_properties = []

    current_schema = copy.deepcopy(partial_schema)

    for each in sample_properties:
      current_schema = utils.detect_nested_attributes_schema(each, current_schema)

    push_event_type_res = self._push_event_type(key, current_schema)
    if push_event_type_res.get("change_reject_reasons"):
      raise ValueError("Event Type not accepted: {}".format(push_event_type_res.get("change_reject_reasons")))
    
    self.__REGISTRY[key] = push_event_type_res["event_type"]

  def event(self,
    id=None,
    type=None, timestamp=None,
    tenant_id=None, properties=None):
    if id is None:
      id = str(uuid.uuid4())
    if type is None or (len(type.strip()) == 0):
      raise ValueError("event type is required")
    if timestamp is None:
      timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if tenant_id is None or (len(tenant_id.strip()) == 0):
      tenant_id = "default"
    if properties is None:
      properties = {}
    if type in self.__REGISTRY:  
      properties_schema = self.__REGISTRY.get(type)["schema"]
    else:
      self.register_event_type(key=type,sample_properties=[properties])
      properties_schema = self.__REGISTRY.get(type)["schema"]

    try:
      normalized_properties = utils.normalize_nested_attributes(properties, schema=properties_schema)
    except ValueError:
      logging.debug("normalisation failed with registered schema. trying to update registery.")
      self.register_event_type(key=type,sample_properties=[properties])
      properties_schema = self.__REGISTRY.get(type)["schema"]
      normalized_properties = utils.normalize_nested_attributes(properties, schema=properties_schema)

    push_event_request_pb = ParseDict({
      "event": {
        "id": id,
        "type": type,
        "timestamp": timestamp,
        "tenant_id": tenant_id,
        "properties": normalized_properties
        }
      },
      events_pb2.PushEventRequest())

    res = self._get_events_stub().pushEvent(push_event_request_pb)
    res_dict = MessageToDict(res,preserving_proto_field_name=True)
    logging.debug("push_event res: {}".format(res_dict))
    return res_dict