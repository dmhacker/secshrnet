from loguru import logger
from datetime import datetime

import redis
import pathlib
import uuid
import threading
import time
import os
import socket
import queue
import configparser
import argparse
import base64

import crypto
import sockutil
import comms_pb2

RECOVER_TIMEOUT_SECONDS = 10


def sanitize_tag(raw_tag):
    return base64.b64encode(raw_tag.encode()).decode()


class Server:

    def __init__(self, config):
        self.share_dir = os.path.join(
            os.path.expandvars(config['Host']['Root']), 'shares')
        pathlib.Path(self.share_dir).mkdir(parents=True, exist_ok=True)
        socket_file = os.path.expandvars(config['Host']['Socket'])
        try:
            os.unlink(socket_file)
        except OSError:
            if os.path.exists(socket_file):
                raise ValueError("Socket file already in use.")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(socket_file)
        self.redis = redis.Redis(
            host=config['Redis']['Host'],
            port=int(config['Redis']['Port']),
            password=config['Redis']['Password'])
        self.pubsub = self.redis.pubsub()
        self.hid = str(uuid.uuid4())
        self.received_packets = queue.Queue()
        self.return_packets = queue.Queue()
        dt_string = datetime.now().strftime("%m-%d-%Y_%H:%M:%S")
        logger.add("logs/secaisle_{}.log".format(dt_string))
        logger.info("Session host ID is {}.".format(self.hid))

    def hosts(self):
        '''
        :param Server self: The active Server object
        :return: List of active host IDs
        :rtype: [str]
        '''
        channels = self.redis.pubsub_channels('secaisle:host:*')

        def extract_host(channel):
            return channel.decode()[len('secaisle:host:'):]

        return [extract_host(channel) for channel in channels]

    def split_plaintext(self, tag, plaintext, threshold):
        '''
        :param Server self: The active Server object
        :param str tag: The tag that this message will get filed under
        :param bytes plaintext: Plaintext message (in bytes)
        :param int threshold: Minimum number of shares needed for recreation
        '''
        hkeys = self.hosts()
        shares = crypto.split_shares(plaintext, threshold, len(hkeys))
        for i, hid in enumerate(hkeys):
            packet = comms_pb2.Packet()
            packet.type = comms_pb2.PacketType.STORE_SHARE
            packet.sender = self.hid
            packet.tag = tag
            packet.share.index = shares[i].index
            packet.share.key_share = shares[i].key_share
            packet.share.ciphertext = shares[i].ciphertext
            packet.share.ciphertext_hash = shares[i].ciphertext_hash
            self.redis.publish('secaisle:host:' + hid,
                               packet.SerializeToString())

    def _collect_return_packets(self, timeout_duration):
        '''
        Private method that blocks the current thread for at least
        {timeout_duration} seconds, waiting for the packet processor
        to funnel in return packets from other hosts.
        '''
        hkeys = self.hosts()
        timestamp = time.time() + timeout_duration
        packets = []
        while True:
            try:
                timeout = timestamp - time.time()
                if timeout <= 0:
                    break
                packet = self.return_packets.get(timeout=timeout)
                if packet.sender in hkeys:
                    packets.append(packet)
                    hkeys.remove(packet.sender)
                    if len(hkeys) == 0:
                        break
            except queue.Empty:
                break
        for bad_host in hkeys:
            logger.warning("Host {} timed out.".format(bad_host))
        return packets

    def combine_shares(self, tag):
        '''
        :param Server self: The active Server object
        :param str tag: The tag for the message we want to fetch
        :return: The message if it could be recovered, otherwise None
        :rtype bytes:
        '''
        packet = comms_pb2.Packet()
        packet.type = comms_pb2.PacketType.RECOVER_SHARE
        packet.sender = self.hid
        packet.tag = tag
        self.redis.publish('secaisle:broadcast', packet.SerializeToString())
        packets = self._collect_return_packets(RECOVER_TIMEOUT_SECONDS)
        shares = [p.share for p in packets if
                  p.type == comms_pb2.PacketType.RETURN_SHARE]
        return crypto.combine_shares(shares)

    def _packet_listener(self):
        '''
        The packet listener subscribes to two channels on Redis, the broadcast
        channel and the host's private channel. It will continually poll for
        packets and forward them to the packet processor.
        '''
        self.pubsub.subscribe('secaisle:broadcast')
        self.pubsub.subscribe('secaisle:host:' + self.hid)
        logger.info("Packet listener thread is now online.")
        for message in self.pubsub.listen():
            if message['type'] == 'message':
                packet = comms_pb2.Packet()
                try:
                    packet.ParseFromString(message['data'])
                    self.received_packets.put(packet)
                except Exception:
                    logger.warning("Unparsable packet on channel {}."
                                   .format(message['channel']))

    def _packet_processor(self):
        '''
        The packet processor is responsible for dealing with incoming
        packets. It will wait on a blocking queue for packets to be
        inserted from the packet listener thread.
        '''
        logger.info("Packet processing thread is now online.")
        while True:
            packet = self.received_packets.get()
            if packet.type == comms_pb2.PacketType.STORE_SHARE:
                logger.info("Saving share for tag '{}' from host {}."
                            .format(packet.tag, packet.sender))
                tagpath = os.path.join(self.share_dir,
                                       sanitize_tag(packet.tag))
                if os.path.exists(tagpath):
                    logger.warning('{} is being overwritten.'
                                   .format(tagpath))
                with open(tagpath, 'wb') as f:
                    f.write(packet.share.SerializeToString())
            elif packet.type == comms_pb2.PacketType.RECOVER_SHARE:
                tagpath = os.path.join(self.share_dir,
                                       sanitize_tag(packet.tag))
                response = comms_pb2.Packet()
                response.sender = self.hid
                if os.path.exists(tagpath):
                    response.type = comms_pb2.PacketType.RETURN_SHARE
                    with open(tagpath, 'rb') as f:
                        response.share.ParseFromString(f.read())
                    logger.info("Sending a '{}' share to host {}."
                                .format(packet.tag, packet.sender))
                else:
                    response.type = comms_pb2.PacketType.NO_SHARE
                    logger.warning("Unable to send a '{}' share to host {}."
                                   .format(packet.tag, packet.sender))
                self.redis.publish('secaisle:host:' + packet.sender,
                                   response.SerializeToString())
            elif packet.type == comms_pb2.PacketType.RETURN_SHARE:
                logger.info("Host {} gave us their share."
                            .format(packet.sender, packet.tag))
                self.return_packets.put(packet)
            elif packet.type == comms_pb2.PacketType.NO_SHARE:
                logger.warning("Host {} did not have a share."
                               .format(packet.sender))
                self.return_packets.put(packet)
            else:
                logger.warning("Unknown packet type {}.".format(
                    packet.type))

    def _command_processor(self):
        '''
        The command processor is responsible for listening on a UNIX
        socket and fielding commands from clients who join via the socket.
        '''
        self.sock.listen(1)
        logger.info("Now accepting commands from clients.")
        while True:
            conn, client_addr = self.sock.accept()
            try:
                while True:
                    message = sockutil.recv_msg(conn)
                    if message is None:
                        break
                    command = comms_pb2.Command()
                    command.ParseFromString(message)
                    response = comms_pb2.Response()
                    if command.type == comms_pb2.CommandType.NUM_HOSTS:
                        logger.info("NUM_HOSTS command received.")
                        response.success = True
                        response.num_hosts = len(self.hosts())
                    elif command.type == comms_pb2.CommandType.SPLIT:
                        logger.info("SPLIT '{}' command received."
                                    .format(command.tag))
                        try:
                            self.split_plaintext(command.tag,
                                                 command.plaintext,
                                                 command.threshold)
                            response.success = True
                        except crypto.ShareError as e:
                            response.success = False
                            response.error = str(e)
                    elif command.type == comms_pb2.CommandType.COMBINE:
                        logger.info("COMBINE '{}' command received."
                                    .format(command.tag))
                        try:
                            response.plaintext = self.combine_shares(
                                command.tag)
                            response.success = True
                        except crypto.ShareError as e:
                            response.success = False
                            response.error = str(e)
                    else:
                        response.success = False
                        response.error = ("Unknown command type {}."
                                          .format(command.type))
                    try:
                        sockutil.send_msg(conn, response.SerializeToString())
                    except BrokenPipeError:
                        pass
            finally:
                conn.close()

    def run(self):
        '''
        Run the server. This will block the calling thread.
        '''
        threads = []
        threads.append(threading.Thread(target=self._packet_listener,
                                        daemon=True))
        threads.append(threading.Thread(target=self._packet_processor,
                                        daemon=True))
        for thr in threads:
            thr.start()
        self._command_processor()


def main():
    parser = argparse.ArgumentParser(
        description='Run a secaisle hosting server.')
    parser.add_argument('-c', '--config', default='default.ini',
                        help='path to the server config file')
    args = parser.parse_args()
    config = configparser.ConfigParser()
    config.read(args.config)
    Server(config).run()


if __name__ == '__main__':
    main()
