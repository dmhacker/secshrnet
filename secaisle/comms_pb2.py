# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: comms.proto

from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='comms.proto',
  package='secaisle',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=b'\n\x0b\x63omms.proto\x12\x08secaisle\"V\n\x05Share\x12\r\n\x05index\x18\x01 \x01(\r\x12\x11\n\tkey_share\x18\x02 \x01(\t\x12\x12\n\nciphertext\x18\x03 \x01(\t\x12\x17\n\x0f\x63iphertext_hash\x18\x04 \x01(\t\"|\n\x06Packet\x12\"\n\x04type\x18\x01 \x01(\x0e\x32\x14.secaisle.PacketType\x12\x0e\n\x06sender\x18\x02 \x01(\t\x12\x11\n\tneeds_ack\x18\x03 \x01(\x08\x12\x0b\n\x03tag\x18\x04 \x01(\t\x12\x1e\n\x05share\x18\x05 \x01(\x0b\x32\x0f.secaisle.Share\"a\n\x07\x43ommand\x12#\n\x04type\x18\x01 \x01(\x0e\x32\x15.secaisle.CommandType\x12\x11\n\tthreshold\x18\x02 \x01(\r\x12\x0b\n\x03tag\x18\x03 \x01(\t\x12\x11\n\tplaintext\x18\x04 \x01(\t\"B\n\x08Response\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x12\n\nhost_count\x18\x02 \x01(\r\x12\x11\n\tplaintext\x18\x03 \x01(\t*9\n\nPacketType\x12\x07\n\x03IAM\x10\x00\x12\t\n\x05STORE\x10\x01\x12\x0b\n\x07RECOVER\x10\x02\x12\n\n\x06RETURN\x10\x03*4\n\x0b\x43ommandType\x12\r\n\tNUM_HOSTS\x10\x00\x12\t\n\x05SPLIT\x10\x01\x12\x0b\n\x07\x43OMBINE\x10\x02\x62\x06proto3'
)

_PACKETTYPE = _descriptor.EnumDescriptor(
  name='PacketType',
  full_name='secaisle.PacketType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='IAM', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='STORE', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='RECOVER', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='RETURN', index=3, number=3,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=406,
  serialized_end=463,
)
_sym_db.RegisterEnumDescriptor(_PACKETTYPE)

PacketType = enum_type_wrapper.EnumTypeWrapper(_PACKETTYPE)
_COMMANDTYPE = _descriptor.EnumDescriptor(
  name='CommandType',
  full_name='secaisle.CommandType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NUM_HOSTS', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SPLIT', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='COMBINE', index=2, number=2,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=465,
  serialized_end=517,
)
_sym_db.RegisterEnumDescriptor(_COMMANDTYPE)

CommandType = enum_type_wrapper.EnumTypeWrapper(_COMMANDTYPE)
IAM = 0
STORE = 1
RECOVER = 2
RETURN = 3
NUM_HOSTS = 0
SPLIT = 1
COMBINE = 2



_SHARE = _descriptor.Descriptor(
  name='Share',
  full_name='secaisle.Share',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='index', full_name='secaisle.Share.index', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='key_share', full_name='secaisle.Share.key_share', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ciphertext', full_name='secaisle.Share.ciphertext', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ciphertext_hash', full_name='secaisle.Share.ciphertext_hash', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=25,
  serialized_end=111,
)


_PACKET = _descriptor.Descriptor(
  name='Packet',
  full_name='secaisle.Packet',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='secaisle.Packet.type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sender', full_name='secaisle.Packet.sender', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='needs_ack', full_name='secaisle.Packet.needs_ack', index=2,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='tag', full_name='secaisle.Packet.tag', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='share', full_name='secaisle.Packet.share', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=113,
  serialized_end=237,
)


_COMMAND = _descriptor.Descriptor(
  name='Command',
  full_name='secaisle.Command',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='secaisle.Command.type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='threshold', full_name='secaisle.Command.threshold', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='tag', full_name='secaisle.Command.tag', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='plaintext', full_name='secaisle.Command.plaintext', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=239,
  serialized_end=336,
)


_RESPONSE = _descriptor.Descriptor(
  name='Response',
  full_name='secaisle.Response',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='success', full_name='secaisle.Response.success', index=0,
      number=1, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='host_count', full_name='secaisle.Response.host_count', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='plaintext', full_name='secaisle.Response.plaintext', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=338,
  serialized_end=404,
)

_PACKET.fields_by_name['type'].enum_type = _PACKETTYPE
_PACKET.fields_by_name['share'].message_type = _SHARE
_COMMAND.fields_by_name['type'].enum_type = _COMMANDTYPE
DESCRIPTOR.message_types_by_name['Share'] = _SHARE
DESCRIPTOR.message_types_by_name['Packet'] = _PACKET
DESCRIPTOR.message_types_by_name['Command'] = _COMMAND
DESCRIPTOR.message_types_by_name['Response'] = _RESPONSE
DESCRIPTOR.enum_types_by_name['PacketType'] = _PACKETTYPE
DESCRIPTOR.enum_types_by_name['CommandType'] = _COMMANDTYPE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Share = _reflection.GeneratedProtocolMessageType('Share', (_message.Message,), {
  'DESCRIPTOR' : _SHARE,
  '__module__' : 'comms_pb2'
  # @@protoc_insertion_point(class_scope:secaisle.Share)
  })
_sym_db.RegisterMessage(Share)

Packet = _reflection.GeneratedProtocolMessageType('Packet', (_message.Message,), {
  'DESCRIPTOR' : _PACKET,
  '__module__' : 'comms_pb2'
  # @@protoc_insertion_point(class_scope:secaisle.Packet)
  })
_sym_db.RegisterMessage(Packet)

Command = _reflection.GeneratedProtocolMessageType('Command', (_message.Message,), {
  'DESCRIPTOR' : _COMMAND,
  '__module__' : 'comms_pb2'
  # @@protoc_insertion_point(class_scope:secaisle.Command)
  })
_sym_db.RegisterMessage(Command)

Response = _reflection.GeneratedProtocolMessageType('Response', (_message.Message,), {
  'DESCRIPTOR' : _RESPONSE,
  '__module__' : 'comms_pb2'
  # @@protoc_insertion_point(class_scope:secaisle.Response)
  })
_sym_db.RegisterMessage(Response)


# @@protoc_insertion_point(module_scope)
