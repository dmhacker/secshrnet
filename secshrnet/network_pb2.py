# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: network.proto

from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='network.proto',
  package='secshrnet',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=b'\n\rnetwork.proto\x12\tsecshrnet\"V\n\x05Share\x12\r\n\x05index\x18\x01 \x01(\r\x12\x11\n\tkey_share\x18\x02 \x01(\x0c\x12\x12\n\nciphertext\x18\x03 \x01(\x0c\x12\x17\n\x0f\x63iphertext_hash\x18\x04 \x01(\x0c\".\n\x07Machine\x12\n\n\x02os\x18\x01 \x01(\t\x12\n\n\x02ip\x18\x02 \x01(\t\x12\x0b\n\x03loc\x18\x03 \x01(\t\"\xa2\x01\n\x06Packet\x12#\n\x04type\x18\x01 \x01(\x0e\x32\x15.secshrnet.PacketType\x12\x0e\n\x06sender\x18\x02 \x01(\t\x12\x0b\n\x03tag\x18\x04 \x01(\t\x12\x1f\n\x05share\x18\x05 \x01(\x0b\x32\x10.secshrnet.Share\x12\x10\n\x08hex_tags\x18\x06 \x01(\t\x12#\n\x07machine\x18\x07 \x01(\x0b\x32\x12.secshrnet.Machine*\xa3\x01\n\nPacketType\x12\x0f\n\x0bSTORE_SHARE\x10\x00\x12\x11\n\rRECOVER_SHARE\x10\x01\x12\x10\n\x0cRETURN_SHARE\x10\x02\x12\x0c\n\x08NO_SHARE\x10\x03\x12\r\n\tLIST_TAGS\x10\x04\x12\x0f\n\x0bRETURN_TAGS\x10\x05\x12\x0b\n\x07NO_TAGS\x10\x06\x12\x10\n\x0cINFO_MACHINE\x10\x07\x12\x12\n\x0eRETURN_MACHINE\x10\x08\x62\x06proto3'
)

_PACKETTYPE = _descriptor.EnumDescriptor(
  name='PacketType',
  full_name='secshrnet.PacketType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='STORE_SHARE', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='RECOVER_SHARE', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='RETURN_SHARE', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='NO_SHARE', index=3, number=3,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LIST_TAGS', index=4, number=4,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='RETURN_TAGS', index=5, number=5,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='NO_TAGS', index=6, number=6,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='INFO_MACHINE', index=7, number=7,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='RETURN_MACHINE', index=8, number=8,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=330,
  serialized_end=493,
)
_sym_db.RegisterEnumDescriptor(_PACKETTYPE)

PacketType = enum_type_wrapper.EnumTypeWrapper(_PACKETTYPE)
STORE_SHARE = 0
RECOVER_SHARE = 1
RETURN_SHARE = 2
NO_SHARE = 3
LIST_TAGS = 4
RETURN_TAGS = 5
NO_TAGS = 6
INFO_MACHINE = 7
RETURN_MACHINE = 8



_SHARE = _descriptor.Descriptor(
  name='Share',
  full_name='secshrnet.Share',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='index', full_name='secshrnet.Share.index', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='key_share', full_name='secshrnet.Share.key_share', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ciphertext', full_name='secshrnet.Share.ciphertext', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ciphertext_hash', full_name='secshrnet.Share.ciphertext_hash', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
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
  serialized_start=28,
  serialized_end=114,
)


_MACHINE = _descriptor.Descriptor(
  name='Machine',
  full_name='secshrnet.Machine',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='os', full_name='secshrnet.Machine.os', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ip', full_name='secshrnet.Machine.ip', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='loc', full_name='secshrnet.Machine.loc', index=2,
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
  serialized_start=116,
  serialized_end=162,
)


_PACKET = _descriptor.Descriptor(
  name='Packet',
  full_name='secshrnet.Packet',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='secshrnet.Packet.type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sender', full_name='secshrnet.Packet.sender', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='tag', full_name='secshrnet.Packet.tag', index=2,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='share', full_name='secshrnet.Packet.share', index=3,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='hex_tags', full_name='secshrnet.Packet.hex_tags', index=4,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='machine', full_name='secshrnet.Packet.machine', index=5,
      number=7, type=11, cpp_type=10, label=1,
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
  serialized_start=165,
  serialized_end=327,
)

_PACKET.fields_by_name['type'].enum_type = _PACKETTYPE
_PACKET.fields_by_name['share'].message_type = _SHARE
_PACKET.fields_by_name['machine'].message_type = _MACHINE
DESCRIPTOR.message_types_by_name['Share'] = _SHARE
DESCRIPTOR.message_types_by_name['Machine'] = _MACHINE
DESCRIPTOR.message_types_by_name['Packet'] = _PACKET
DESCRIPTOR.enum_types_by_name['PacketType'] = _PACKETTYPE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Share = _reflection.GeneratedProtocolMessageType('Share', (_message.Message,), {
  'DESCRIPTOR' : _SHARE,
  '__module__' : 'network_pb2'
  # @@protoc_insertion_point(class_scope:secshrnet.Share)
  })
_sym_db.RegisterMessage(Share)

Machine = _reflection.GeneratedProtocolMessageType('Machine', (_message.Message,), {
  'DESCRIPTOR' : _MACHINE,
  '__module__' : 'network_pb2'
  # @@protoc_insertion_point(class_scope:secshrnet.Machine)
  })
_sym_db.RegisterMessage(Machine)

Packet = _reflection.GeneratedProtocolMessageType('Packet', (_message.Message,), {
  'DESCRIPTOR' : _PACKET,
  '__module__' : 'network_pb2'
  # @@protoc_insertion_point(class_scope:secshrnet.Packet)
  })
_sym_db.RegisterMessage(Packet)


# @@protoc_insertion_point(module_scope)
