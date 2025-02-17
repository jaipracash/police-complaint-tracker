from six import viewitems
from six import (string_types,
  integer_types, text_type)

import logging

import sys
from setuptools import find_packages
from pkgutil import iter_modules

import typing
import types
import inspect

# Python >= 3.8
if hasattr(typing, "get_origin"):
  typing_get_origin = typing.get_origin
  typing_get_args = typing.get_args

else:
  typing_get_origin = lambda t: getattr(t, '__origin__', None)
  typing_get_args = lambda t: getattr(t, '__args__', ()) if t is not typing.Generic else typing.Generic

if hasattr(types, "UnionType"):
  typing_UnionType = types.UnionType
  typing_NoneType = types.NoneType
else:
  typing_UnionType = typing.Union
  typing_NoneType = type(None)

def detect_attribute_type(value):
  if isinstance(value, bool):
    return "BOOL"
  elif isinstance(value, float):
    return "DOUBLE"
  elif isinstance(value, integer_types):
    return "INT"
  elif isinstance(value, string_types+(text_type,)):
    return "STRING"
  elif isinstance(value, list):
    return "OBJECT"
  elif isinstance(value, dict):
    return "OBJECT"
  else:
    return None

def detect_nested_attributes_schema(nested_attributes, schema=None):
  if schema is None:
    schema = {}
  
  schema["type"] = schema.get("type") or "OBJECT"
  schema["repeatable"] = schema.get("repeatable") or False
  schema["properties"] = schema.get("properties") or {}
  schema["allow_unknown_properties"] = schema.get("allow_unknown_properties") or False
  if schema["allow_unknown_properties"]:
    schema["unknown_property_schema"] = schema.get("unknown_property_schema") or {"type": "STRING"}
  else:
    schema["unknown_property_schema"] = schema.get("unknown_property_schema") or {}


  for (key, value) in viewitems(nested_attributes):
    attribute_type = None
    repeatable = False
    
    if value is None:
      continue
    if isinstance(value, list):
      try:
        attribute_type = detect_attribute_type(value[0])
      except IndexError:
        continue
      repeatable = True
    else:
      attribute_type = detect_attribute_type(value)

    if attribute_type is None:
      continue

    item_schema = None
    if attribute_type == "OBJECT":
      item_schema = {}
      if isinstance(value, list):
        for each_value in value:
          item_schema.update(detect_nested_attributes_schema(each_value, schema=schema["properties"].get(key)))
      else:
        item_schema = detect_nested_attributes_schema(value, schema=schema["properties"].get(key))
    if (schema["allow_unknown_properties"] and
        (schema["unknown_property_schema"].get("type") == attribute_type)):
      continue
    schema["properties"][key] = {
    "type": attribute_type,
    "repeatable": repeatable
    }
    if item_schema:
      schema["properties"][key]["properties"] = item_schema["properties"]
    else:
      schema["properties"][key]["properties"] = {}

  return schema


def _fill_normalize_values(schema_item, normalized, key, value):
  if isinstance(value, list):
    type_set = set(map(detect_attribute_type, value))
    if len(type_set)>1:
      raise ValueError("Multiple type not allowed in list {}".format(type_set))
    elif len(type_set)==1:
      detect_type = type_set.pop()
  else:
    detect_type = detect_attribute_type(value)

  if schema_item["type"] != detect_type:
    raise ValueError("expected {} found {} at key={}, value={}".format(schema_item["type"],detect_type,key, value))

  if schema_item.get("repeatable"):
    if schema_item["type"] == "BOOL":
      normalized["repeated_bools"][key] = {"values": value}
    elif schema_item["type"] == "DOUBLE":
      normalized["repeated_doubles"][key] = {"values": value}
    elif schema_item["type"] == "INT":
      normalized["repeated_ints"][key] = {"values": value}
    elif schema_item["type"] == "STRING":
      normalized["repeated_strings"][key] = {"values": value}
    elif schema_item["type"] == "OBJECT":
      list_value = []
      for each_value in value:
        list_value.append(normalize_nested_attributes(each_value, schema=schema_item))
      normalized["repeated_objects"][key] = {"values": list_value}
  else:
    if schema_item["type"] == "BOOL":
      normalized["bools"][key] = value
    elif schema_item["type"] == "DOUBLE":
      normalized["doubles"][key] = value
    elif schema_item["type"] == "INT":
      normalized["ints"][key] = value
    elif schema_item["type"] == "STRING":
      normalized["strings"][key] = value
    elif schema_item["type"] == "OBJECT":
      normalized["objects"][key] = normalize_nested_attributes(value, schema=schema_item)

def normalize_nested_attributes(nested_attributes, schema=None):
  normalized = {
  "bools": {},
  "doubles": {},
  "ints": {},
  "strings": {},
  "objects": {},

  "repeated_bools": {},
  "repeated_doubles": {},
  "repeated_ints": {},
  "repeated_strings": {},
  "repeated_objects": {}
  }
  if schema is None:
    schema = detect_nested_attributes_schema(nested_attributes)

  if "properties" not in schema:
    schema["properties"] = {}

  if schema.get("repeatable") and schema["type"] == "OBJECT" and set(schema.get("properties").keys()) == {"_SCALAR_VALUE"}:
    if isinstance(nested_attributes, list):
      _fill_normalize_values(schema["properties"]["_SCALAR_VALUE"], normalized, "_SCALAR_VALUE", nested_attributes)
      return normalized

  for (key, schema_item) in viewitems(schema.get("properties")):
    value = nested_attributes.get(key)
    if value is None or value == []:
      continue

    _fill_normalize_values(schema_item, normalized, key, value)
  allow_unknown_properties = schema.get("allow_unknown_properties")
  unknown_property_schema = schema.get("unknown_property_schema")
  unkown_keys = set(nested_attributes.keys()) - set(schema.get("properties").keys())
  none_keys = set()
  for key in unkown_keys:
    if nested_attributes[key] is None or nested_attributes[key] == []:
      none_keys.add(key)
  unkown_keys = unkown_keys - none_keys
  if allow_unknown_properties and unknown_property_schema:
    for key in unkown_keys:
      value = nested_attributes[key]
      if value is None:
        continue
      _fill_normalize_values(unknown_property_schema, normalized, key, value)
  elif unkown_keys:
    raise ValueError("unkown_keys: " + ",".join(unkown_keys))

  return normalized

def detect_attribute_is_required_from_type(type):
  type_origin = typing_get_origin(type)
  type_args = typing_get_args(type)
  if type_origin is typing_UnionType and (typing_NoneType in type_args):
    return False

  return True

def detect_attribute_type_from_type(type):
  type_origin = typing_get_origin(type)
  type_args = typing_get_args(type)
  if type_origin is typing_UnionType and len(type_args) == 2 and type_args[1] is typing_NoneType:
    type = type_args[0]

  if type is bool:
    return "BOOL"
  elif type is float:
    return "DOUBLE"
  elif type in integer_types:
    return "INT"
  elif type in string_types+(text_type,):
    return "STRING"
  else:
    return None

def detect_function_parameters_schema(function):
  signature = inspect.signature(function)
  schema = {
  "type": "OBJECT",
  "properties": {}
  }
  errors = []
  for param_key, param in viewitems(signature.parameters):
    if param.annotation is inspect._empty:
      errors.append("Missing type annotation. key={}".format(param_key))
      continue
    detected_type = detect_attribute_type_from_type(param.annotation)
    if param.default is None:# only when default is declared as None, if default is left it is inspect._empty
      is_required = False
    else:
      is_required = detect_attribute_is_required_from_type(param.annotation)
    if detected_type is None:
      errors.append("Unsupported type {}. key={}".format(param.annotation, param_key))
      continue
    schema["properties"][param_key] = {"type": detected_type, "required": is_required}
  
  if errors:
    raise ValueError("\n".join(errors))

  return schema

def detect_function_result_schema(function):
  signature = inspect.signature(function)
  type = signature.return_annotation

  if type is None or type is inspect._empty:
    return None

  type_origin = typing_get_origin(type)
  type_args = typing_get_args(type)
  

  schema = {
  "type": "OBJECT",
  "properties": {}
  }
  errors = []
  
  if type_origin is dict and type_args == (str,str): #dict[str,str]
    schema["allow_unknown_properties"] = True
    schema["unknown_property_schema"] = {"type": "STRING"}
  elif type_origin is dict and type_args == (str,int): #dict[str,int]
    schema["allow_unknown_properties"] = True
    schema["unknown_property_schema"] = {"type": "INT"}
  elif type_origin is dict and type_args == (str,float): #dict[str,float]:
    schema["allow_unknown_properties"] = True
    schema["unknown_property_schema"] = {"type": "DOUBLE"}
  elif type_origin is dict and type_args == (str,bool): #dict[str,bool]:
    schema["allow_unknown_properties"] = True
    schema["unknown_property_schema"] = {"type": "BOOL"}
  elif type_origin is list and type_args == (str,): #list[str]:
    schema["properties"] = {"_RETURN_VALUE":{"type":"STRING", "repeatable": True}}
  elif type_origin is list and type_args == (int,): #list[int]:
    schema["properties"] = {"_RETURN_VALUE":{"type":"INT", "repeatable": True}}
  elif type_origin is list and type_args == (float,): #list[float]:
    schema["properties"] = {"_RETURN_VALUE":{"type":"DOUBLE", "repeatable": True}}
  elif type_origin is list and type_args == (bool,): #list[bool]:
    schema["properties"] = {"_RETURN_VALUE":{"type":"BOOL", "repeatable": True}}
  elif type_origin is list and type_args == (list[str],): #list[list[..]]:
    schema["properties"] = {"_RETURN_VALUE": {
      "type": "OBJECT",
      "properties": {"_SCALAR_VALUE": {"type":"STRING", "repeatable": True}},
      "repeatable": True
      }
      }
  elif type == str:
    schema["properties"] = {"_RETURN_VALUE":{"type":"STRING"}}
  elif type == int:
    schema["properties"] = {"_RETURN_VALUE":{"type":"INT"}}
  elif type == float:
    schema["properties"] = {"_RETURN_VALUE":{"type":"DOUBLE"}}
  elif type == bool:
    schema["properties"] = {"_RETURN_VALUE":{"type":"BOOL"}}
  else:
    errors.append("Unsupported return type: {}".format(type))

  if errors:
    raise ValueError("\n".join(errors))
  else:
    return schema

def parameters_to_python(parameters, schema):
  if schema.get("properties") is None:
    schema["properties"] = {}
  args = []
  kwargs = {}
  for kind_key in ("strings", "ints", "doubles", "bools"):
    for key, value in viewitems(getattr(parameters, kind_key)):
      kwargs[key] = value

  missing_keys = set(schema["properties"].keys()) - set(kwargs.keys())

  for each in missing_keys:
    kwargs[each] = None

  return (args,kwargs)

def python_to_parameters(parameters, schema): #for result
  if isinstance(parameters, dict):
    return normalize_nested_attributes(parameters, schema)
  else:
    return normalize_nested_attributes({"_RETURN_VALUE": parameters}, schema)

def auto_load_modules(path):
  modules = set()
  for pkg in find_packages(path):
    modules.add(pkg)
    pkgpath = path + '/' + pkg.replace('.', '/')
    if sys.version_info.major == 2 or (sys.version_info.major == 3 and sys.version_info.minor < 6):
      for _, name, ispkg in iter_modules([pkgpath]):
        if not ispkg:
          modules.add(pkg + '.' + name)
    else:
      for info in iter_modules([pkgpath]):
        if not info.ispkg:
          modules.add(pkg + '.' + info.name)

  for each in modules:
    logging.info("Loading module {}".format(each))
    __import__(each)


class TerminalStyles:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'


def use_default_logging():
  logging.basicConfig(
      level=logging.INFO
      #format='%(asctime)s | %(name)s | [%(pathname)s %(funcName)s %(lineno)d] | %(levelname)s | %(message)s'
      )