from loguru import logger

import configparser
import argparse
import sys
import getpass
import redis
import uuid
import queue
import time

import crypto
import comms_pb2
import host

RECOVER_TIMEOUT_SECONDS = 10


class ClientError(Exception):
    pass


class Client(host.Host):

    def __init__(self, config):
        super().__init__('secshrnet:client:', config)
        self.collected_packets = None
        logger.remove(handler_id=None)

    def servers(self):
        return self.connected_hosts('secshrnet:server:')

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
            self.redis.publish('secshrnet:server:' + hid,
                               packet.SerializeToString())

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

    def recombine(self, tag):
        packet = comms_pb2.Packet()
        packet.type = comms_pb2.PacketType.RECOVER_SHARE
        packet.sender = self.hid
        packet.tag = tag
        for hid in self.servers():
            self.redis.publish('secshrnet:server:' + hid,
                               packet.SerializeToString())
        packets = self._collect_packets(RECOVER_TIMEOUT_SECONDS)
        shares = [p.share for p in packets if
                  p.type == comms_pb2.PacketType.RETURN_SHARE]
        return crypto.combine_shares(shares)

    def handle_packet(self, packet):
        if packet.type == comms_pb2.PacketType.RETURN_SHARE or \
                packet.type == comms_pb2.PacketType.NO_SHARE:
            if self.collected_packets:
                self.collected_packets.put(packet)


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


def main():
    parser = argparse.ArgumentParser(
        description='Send to and receive from a secshrnet network.')
    parser.add_argument('-s', '--split', action='store_true',
                        help='split a file, upload it to the network')
    parser.add_argument('-c', '--combine', action='store_true',
                        help='combine data in the network, store to file')
    parser.add_argument('--config', default='default.ini',
                        help='path to the configuration file')
    parser.add_argument('tag', help='unique tag location')
    parser.add_argument('file', help='file to upload from or download to')
    args = parser.parse_args()
    if args.split == args.combine:
        print("Please specify either --split or --combine.", file=sys.stderr)
        sys.exit(1)
        return
    config = configparser.ConfigParser()
    config.read(args.config)
    client = Client(config)
    client.run(block=False)
    num_servers = len(client.servers())
    if num_servers == 0:
        print("No servers online.")
        return
    print("Found {} servers on the network.".format(num_servers))
    try:
        if args.split:
            threshold = read_threshold(num_servers)
            password = read_password(args.tag)
            with open(args.file, 'rb') as f:
                pt = f.read()
                ct = crypto.encrypt_plaintext(pt, password)
                client.split(args.tag, ct, threshold)
            print("Contents of {} uploaded to tag '{}'."
                  .format(args.file, args.tag))
        else:
            ct = client.recombine(args.tag)
            password = read_password(args.tag)
            pt = crypto.decrypt_ciphertext(ct, password)
            if pt is None:
                raise ClientError("Incorrect password.")
            with open(args.file, 'wb') as f:
                f.write(pt)
            print("Data for tag '{}' downloaded into {}."
                  .format(args.tag, args.file))
    except ClientError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
