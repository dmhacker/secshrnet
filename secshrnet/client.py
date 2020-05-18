from loguru import logger
from collections import Counter

import configparser
import argparse
import sys
import getpass
import queue
import itertools
import time
import base64

from . import crypto
from . import comms_pb2
from . import host
# import crypto
# import comms_pb2
# import host

RECOVER_TIMEOUT_SECONDS = 10
LIST_TIMEOUT_SECONDS = 10


def decode_tag(hex_tag):
    return base64.b16decode(hex_tag.encode()).decode()


def read_threshold(num_hosts):
    while True:
        default_threshold = num_hosts // 2 + 1
        threshold_str = input(("Minimum shares needed for "
                               "reconstruction (default = {}): ")
                              .format(default_threshold))
        if threshold_str == "":
            threshold = default_threshold
            break
        try:
            threshold = int(threshold_str)
            if threshold >= 1 and threshold <= num_hosts:
                break
        except ValueError:
            pass
        print("Please enter a number between 1 and {}."
              .format(num_hosts), file=sys.stderr)
    return threshold


def read_password(tag):
    return crypto.hash256(getpass.getpass("Password for tag '{}': "
                                          .format(tag)).encode('utf-8'))


class Client(host.Host):

    def __init__(self, config):
        super().__init__('secshrnet:client:', config)
        self.collected_packets = None
        logger.remove(handler_id=None)

    def handle_packet(self, packet):
        if packet.type == comms_pb2.PacketType.RETURN_SHARE or \
                packet.type == comms_pb2.PacketType.NO_SHARE or \
                packet.type == comms_pb2.PacketType.RETURN_TAGS or \
                packet.type == comms_pb2.PacketType.NO_TAGS:
            if self.collected_packets:
                self.collected_packets.put(packet)

    def servers(self):
        return self.connected_hosts('secshrnet:server:')

    def _collect_packets(self, timeout_duration):
        servset = self.servers()
        timestamp = time.time() + timeout_duration
        packets = []
        self.collected_packets = queue.Queue()
        while True:
            try:
                timeout = timestamp - time.time()
                if timeout <= 0:
                    break
                packet = self.collected_packets.get(timeout=timeout)
                if packet.sender in servset:
                    packets.append(packet)
                    servset.remove(packet.sender)
                    if len(servset) == 0:
                        break
            except queue.Empty:
                break
        self.collected_packets = None
        return packets

    def split(self, tag, plaintext, threshold):
        servset = self.servers()
        shares = crypto.split_shares(plaintext, threshold, len(servset))
        for i, hid in enumerate(servset):
            packet = comms_pb2.Packet()
            packet.type = comms_pb2.PacketType.STORE_SHARE
            packet.sender = self.hid
            packet.tag = tag
            packet.share.index = shares[i].index
            packet.share.key_share = shares[i].key_share
            packet.share.ciphertext = shares[i].ciphertext
            packet.share.ciphertext_hash = shares[i].ciphertext_hash
            self.send_packet('secshrnet:server:' + hid, packet)

    def combine(self, tag):
        packet = comms_pb2.Packet()
        packet.type = comms_pb2.PacketType.RECOVER_SHARE
        packet.sender = self.hid
        packet.tag = tag
        for hid in self.servers():
            self.send_packet('secshrnet:server:' + hid, packet)
        packets = self._collect_packets(RECOVER_TIMEOUT_SECONDS)
        shares = [p.share for p in packets if
                  p.type == comms_pb2.PacketType.RETURN_SHARE]
        return crypto.combine_shares(shares)

    def list_tags(self):
        packet = comms_pb2.Packet()
        packet.type = comms_pb2.PacketType.LIST_TAGS
        packet.sender = self.hid
        servset = self.servers()
        for hid in servset:
            self.send_packet('secshrnet:server:' + hid, packet)
        packets = self._collect_packets(LIST_TIMEOUT_SECONDS)
        hex_tags = [p.tag for p in packets if
                    p.type == comms_pb2.PacketType.RETURN_TAGS]
        tag_groups = [tag.split(',') for tag in hex_tags]
        hex_tags = list(itertools.chain(*tag_groups))
        tags = [decode_tag(tag) for tag in hex_tags]
        return list(Counter(tags).items())

    def handle_command(self, args, num_servers):
        if num_servers == 0:
            print("No active servers on the network.")
            return
        command = args[0].lower()
        if command == "split":
            if len(args) < 3:
                print("Usage: split <TAG> <FILE>")
                return
            tag = args[1]
            filepath = ' '.join(args[2:])
            threshold = read_threshold(num_servers)
            password = read_password(tag)
            with open(filepath, 'rb') as f:
                pt = f.read()
                ct = crypto.encrypt_plaintext(pt, password)
                client.split(tag, ct, threshold)
            print("Contents of {} uploaded to tag '{}'."
                .format(filepath, tag))
        elif command == "combine":
            if len(args) < 3:
                print("Usage: combine <TAG> <FILE>")
                return
            tag = args[1]
            filepath = ' '.join(args[2:])
            ct = client.combine(tag)
            password = read_password(tag)
            pt = crypto.decrypt_ciphertext(ct, password)
            if pt is None:
                raise crypto.ShareError("Incorrect password.")
            with open(filepath, 'wb') as f:
                f.write(pt)
            print("Data for tag '{}' downloaded into {}."
                .format(tag, filepath))
        elif command == "tags":
            tags = self.list_tags()
            if len(tags) == 0:
                print("No tags available on network.")
            else:
                print("Available tags:")
                for (tag, count) in tags:
                    print("\t- {} ({} servers)".format(tag, count))
        else:
            print("Unable to interpret command.")

    def _command_listener(self):
        while True:
            try:
                num_servers = len(self.servers())
                full_command = input("{} servers> ".format(num_servers))
                self.handle_command(full_command.split(' '), num_servers)
            except crypto.ShareError as e:
                print(str(e))
            except FileNotFoundError as e:
                print(str(e))
            except EOFError:
                print("\nbye")
                break

    def run(self):
        super().run(block=False)
        self._command_listener()


def main():
    parser = argparse.ArgumentParser(
        description='Run a secshrnet client.')
    parser.add_argument('-c', '--config', default='default.ini',
                        help='path to the configuration file')
    args = parser.parse_args()
    config = configparser.ConfigParser()
    config.read(args.config)
    client = Client(config)
    client.run()


if __name__ == '__main__':
    main()
