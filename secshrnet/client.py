from loguru import logger
from colorama import Fore, Style
from collections import Counter
from threading import Lock
from queue import Queue

import os
import configparser
import argparse
import sys
import itertools
import time
import base64

from . import crypto
from . import network_pb2
from . import host
from . import command


def decode_tag(hex_tag):
    return base64.b16decode(hex_tag.encode()).decode()


class Client(host.Host):

    def __init__(self, config):
        super().__init__(config, 'secshrnet:client:')
        self.cli = command.CommandInterface(self)
        self.buffer = Queue()
        self.buffer_types = set()
        self.buffer_mutex = Lock()
        logger.remove(handler_id=None)

    def handle_packet(self, packet):
        with self.buffer_mutex:
            is_valid = packet.type in self.buffer_types
        if is_valid:
            self.buffer.put(packet)

    def servers(self):
        return self.connected_hosts('secshrnet:server:')

    def _open_buffer(self, accepting_types):
        with self.buffer_mutex:
            self.buffer_types.update(accepting_types)

    def _close_buffer(self, timeout_seconds=5):
        servset = self.servers()
        timestamp = time.time() + timeout_seconds
        packets = []
        while True:
            try:
                time_left = timestamp - time.time()
                if time_left <= 0:
                    break
                packet = self.buffer.get(timeout=time_left)
                if packet.sender in servset:
                    packets.append(packet)
                    servset.remove(packet.sender)
                    if len(servset) == 0:
                        break
            except queue.Empty:
                break
        with self.buffer_mutex:
            self.buffer_types.clear()
        self.buffer = Queue()
        return packets

    def split(self, tag, plaintext, threshold):
        servset = self.servers()
        shares = crypto.split_shares(plaintext, threshold, len(servset))
        self._open_buffer({network_pb2.PacketType.ACK_STORE_SHARE})
        for i, hid in enumerate(servset):
            packet = network_pb2.Packet()
            packet.type = network_pb2.PacketType.STORE_SHARE
            packet.sender = self.hid
            packet.tag = tag
            packet.share.index = shares[i].index
            packet.share.key_share = shares[i].key_share
            packet.share.ciphertext = shares[i].ciphertext
            packet.share.ciphertext_hash = shares[i].ciphertext_hash
            self.send_packet('secshrnet:server:' + hid, packet)
        packets = self._close_buffer()
        return [p.sender for p in packets]

    def combine(self, tag):
        packet = network_pb2.Packet()
        packet.type = network_pb2.PacketType.RECOVER_SHARE
        packet.sender = self.hid
        packet.tag = tag
        self._open_buffer({network_pb2.PacketType.ACK_RECOVER_SHARE,
                           network_pb2.PacketType.NAK_RECOVER_SHARE})
        self.send_packet('secshrnet:broadcast', packet)
        packets = self._close_buffer()
        shares = [p.share for p in packets if
                  p.type == network_pb2.PacketType.ACK_RECOVER_SHARE]
        return crypto.combine_shares(shares)

    def tags(self):
        packet = network_pb2.Packet()
        packet.type = network_pb2.PacketType.LIST_TAGS
        packet.sender = self.hid
        self._open_buffer({network_pb2.PacketType.ACK_LIST_TAGS,
                           network_pb2.PacketType.NAK_LIST_TAGS})
        self.send_packet('secshrnet:broadcast', packet)
        packets = self._close_buffer()
        hex_tags = [p.hex_tags for p in packets if
                    p.type == network_pb2.PacketType.ACK_LIST_TAGS]
        tag_groups = [tag.split(',') for tag in hex_tags]
        hex_tags = list(itertools.chain(*tag_groups))
        tags = [decode_tag(tag) for tag in hex_tags]
        return list(Counter(tags).items())

    def server_information(self):
        packet = network_pb2.Packet()
        packet.type = network_pb2.PacketType.INFO_MACHINE
        packet.sender = self.hid
        self._open_buffer({network_pb2.PacketType.ACK_INFO_MACHINE})
        self.send_packet('secshrnet:broadcast', packet)
        packets = self._close_buffer()
        return [(p.sender, p.machine) for p in packets]

    def run(self):
        super().run()
        self.cli.run()


def main():
    parser = argparse.ArgumentParser(
        description='Run a secshrnet client.')
    parser.add_argument('-c', '--config',
                        default=os.path.expandvars(
                            '$HOME/.secshrnet/secshrnet.conf'),
                        help='path to the redis config file')
    args = parser.parse_args()
    config = configparser.ConfigParser()
    with open(args.config, 'r') as f:
        pass
    config.read(args.config)
    Client(config).run()


if __name__ == '__main__':
    main()
