from loguru import logger
from colorama import Fore, Style
from collections import Counter

import configparser
import argparse
import sys
import queue
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
        self.buffer = None
        logger.remove(handler_id=None)

    def handle_packet(self, packet):
        if packet.type == network_pb2.PacketType.RETURN_SHARE or \
                packet.type == network_pb2.PacketType.NO_SHARE or \
                packet.type == network_pb2.PacketType.RETURN_TAGS or \
                packet.type == network_pb2.PacketType.NO_TAGS or \
                packet.type == network_pb2.PacketType.RETURN_MACHINE:
            if self.buffer:
                self.buffer.put(packet)

    def servers(self):
        return self.connected_hosts('secshrnet:server:')

    def _buffer_passively(self):
        self.buffer = queue.Queue()

    def _buffer_actively(self, timeout_seconds=5):
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
        self.buffer = None
        return packets

    def split(self, tag, plaintext, threshold):
        servset = self.servers()
        shares = crypto.split_shares(plaintext, threshold, len(servset))
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

    def combine(self, tag):
        packet = network_pb2.Packet()
        packet.type = network_pb2.PacketType.RECOVER_SHARE
        packet.sender = self.hid
        packet.tag = tag
        self._buffer_passively()
        self.send_packet('secshrnet:broadcast', packet)
        packets = self._buffer_actively()
        shares = [p.share for p in packets if
                  p.type == network_pb2.PacketType.RETURN_SHARE]
        return crypto.combine_shares(shares)

    def tags(self):
        packet = network_pb2.Packet()
        packet.type = network_pb2.PacketType.LIST_TAGS
        packet.sender = self.hid
        self._buffer_passively()
        self.send_packet('secshrnet:broadcast', packet)
        packets = self._buffer_actively()
        hex_tags = [p.hex_tags for p in packets if
                    p.type == network_pb2.PacketType.RETURN_TAGS]
        tag_groups = [tag.split(',') for tag in hex_tags]
        hex_tags = list(itertools.chain(*tag_groups))
        tags = [decode_tag(tag) for tag in hex_tags]
        return list(Counter(tags).items())

    def server_information(self):
        packet = network_pb2.Packet()
        packet.type = network_pb2.PacketType.INFO_MACHINE
        packet.sender = self.hid
        self._buffer_passively()
        self.send_packet('secshrnet:broadcast', packet)
        packets = self._buffer_actively()
        return [(p.sender, p.machine) for p in packets]

    def run(self):
        super().run()
        self.cli.run()


def main():
    parser = argparse.ArgumentParser(
        description='Run a secshrnet client.')
    parser.add_argument('-c', '--config', type=str,
                        help='path to the redis config file')
    args = parser.parse_args()
    config = configparser.ConfigParser()
    if args.config is None:
        args.config = os.path.join(args.root, 'secshrnet.conf')
    config.read(args.config)
    Client(config).run()


if __name__ == '__main__':
    main()
