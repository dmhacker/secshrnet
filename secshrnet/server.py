from loguru import logger

import pathlib
import os
import configparser
import argparse
import base64
import signal
import platform
import time
import shutil

from . import network_pb2
from . import host

IP_EXPIRATION_SECONDS = 3600


def encode_tag(raw_tag):
    return base64.b64encode(raw_tag.encode()).decode()


class Server(host.Host):

    def __init__(self, root_dir, config):
        super().__init__(config, 'secshrnet:server:', 'secshrnet:broadcast')
        self.share_dir = os.path.join(root_dir, 'shares')
        pathlib.Path(self.share_dir).mkdir(parents=True, exist_ok=True)
        logger.add(os.path.join(root_dir, "secshrnetd.log"))
        logger.info("Session host ID is {}.".format(self.hid))

    def handle_packet(self, packet):
        if packet.type == network_pb2.PacketType.STORE_SHARE:
            logger.info("Saving share for tag '{}' from host {}."
                        .format(packet.tag, packet.sender))
            tagpath = os.path.join(self.share_dir, encode_tag(packet.tag))
            if os.path.exists(tagpath):
                logger.warning('{} is being overwritten.'.format(tagpath))
            with open(tagpath, 'wb') as f:
                f.write(packet.share.SerializeToString())
            response = network_pb2.Packet()
            response.sender = self.hid
            response.type = network_pb2.PacketType.ACK_STORE_SHARE
            self.send_packet('secshrnet:client:' + packet.sender, response)
        elif packet.type == network_pb2.PacketType.RECOVER_SHARE:
            tagpath = os.path.join(self.share_dir,
                                   encode_tag(packet.tag))
            response = network_pb2.Packet()
            response.sender = self.hid
            if os.path.exists(tagpath):
                response.type = network_pb2.PacketType.ACK_RECOVER_SHARE
                with open(tagpath, 'rb') as f:
                    response.share.ParseFromString(f.read())
                logger.info("Sending a '{}' share to host {}."
                            .format(packet.tag, packet.sender))
            else:
                response.type = network_pb2.PacketType.NAK_RECOVER_SHARE
                logger.info("No '{}' share to send to host {}."
                            .format(packet.tag, packet.sender))
            self.send_packet('secshrnet:client:' + packet.sender, response)
        elif packet.type == network_pb2.PacketType.LIST_TAGS:
            filenames = [f for f in os.listdir(self.share_dir)
                         if os.path.isfile(os.path.join(self.share_dir, f))]
            response = network_pb2.Packet()
            response.sender = self.hid
            if len(filenames) > 0:
                response.type = network_pb2.PacketType.ACK_LIST_TAGS
                response.hex_tags = ','.join(filenames)
            else:
                response.type = network_pb2.PacketType.NAK_LIST_TAGS
            logger.info("Reporting {} tags to host {}."
                        .format(len(filenames), packet.sender))
            self.send_packet('secshrnet:client:' + packet.sender, response)
        elif packet.type == network_pb2.PacketType.INFO_MACHINE:
            response = network_pb2.Packet()
            response.sender = self.hid
            response.type = network_pb2.PacketType.ACK_INFO_MACHINE
            response.machine.os = "{} {}".format(platform.system(),
                                                 platform.release())
            response.machine.name = platform.node()
            response.machine.free = shutil.disk_usage('/')[2]
            logger.info("Reporting machine information to host {}."
                        .format(packet.sender))
            self.send_packet('secshrnet:client:' + packet.sender, response)
        else:
            logger.warning("Unknown packet type {} from host {}.".format(
                packet.type, packet.sender))

    def run(self):
        super().run()
        signal.pause()


def main():
    parser = argparse.ArgumentParser(
        description='Run a secshrnet hosting server.')
    parser.add_argument('-r', '--root',
                        default=os.path.expandvars('$HOME/.secshrnet'),
                        help='root directory to write shares to')
    parser.add_argument('-c', '--config',
                        help='path to the redis config file')
    args = parser.parse_args()
    config = configparser.ConfigParser()
    if args.config is None:
        args.config = os.path.join(args.root, 'secshrnet.conf')
    with open(args.config, 'r') as f:
        pass
    config.read(args.config)
    Server(args.root, config).run()


if __name__ == '__main__':
    main()
