from expiringdict import ExpiringDict
from queue import Queue
from loguru import logger

import redis
import pathlib
import uuid
import threading
import time
import os
import socket
import base64

import crypto
import sockutil
import comms_pb2

HOST_REFRESH_SECONDS = 1800
HOST_TTL_SECONDS = 3600
SOCKET_FILE = '/tmp/secaisle-socket'
SHARE_DIRECTORY = '{}/.secaisle/shares'.format(os.environ['HOME'])


class Server:

    def __init__(self, redis_host, redis_port, redis_password):
        pathlib.Path(SHARE_DIRECTORY).mkdir(parents=True, exist_ok=True)
        try:
            os.unlink(SOCKET_FILE)
        except OSError:
            if os.path.exists(SOCKET_FILE):
                raise ValueError("Socket address {} is already in use.")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(SOCKET_FILE)
        self.hid = str(uuid.uuid4())
        self.hosts = ExpiringDict(max_len=1e10,
                                  max_age_seconds=HOST_TTL_SECONDS)
        self.redis = redis.Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password)
        self.pubsub = self.redis.pubsub()
        self.received_packets = Queue()
        # This isn't actually necessary, since this server will see
        # itself on the broadcast channel when it issues a ping
        self.hosts[self.hid] = True
        logger.add("logs/secaisle_{}.log".format(self.hid))

    def _packet_listener(self):
        logger.info("Packet listener started.")
        self.pubsub.subscribe('secaisle:broadcast')
        self.pubsub.subscribe('secaisle:host:' + self.hid)
        ping = comms_pb2.Packet()
        ping.type = comms_pb2.PacketType.IAM
        ping.sender = self.hid
        ping.needs_ack = True
        self.redis.publish('secaisle:broadcast', ping.SerializeToString())
        for message in self.pubsub.listen():
            if message['type'] == 'message':
                packet = comms_pb2.Packet()
                packet.ParseFromString(message['data'])
                self.received_packets.put(packet)

    def _packet_processor(self):
        logger.info("Packet processor started.")
        while True:
            packet = self.received_packets.get()
            logger.info("Received packet {} from host {}.".format(
                packet.type, packet.sender))
            if packet.type == comms_pb2.PacketType.IAM:
                self.hosts[packet.sender] = True
                if packet.needs_ack:
                    pong = comms_pb2.Packet()
                    pong.type = comms_pb2.PacketType.IAM
                    pong.sender = self.hid
                    pong.needs_ack = False
                    self.redis.publish('secaisle:host:' + packet.sender,
                                       pong.SerializeToString())
            elif packet.type == comms_pb2.PacketType.STORE:
                tagpath = os.path.join(SHARE_DIRECTORY, packet.tag)
                logger.info("Storing share to tag '{}' @ {}."
                            .format(packet.tag, tagpath))
                if os.path.exists(tagpath):
                    logger.warning('{} is being overwritten.'
                                   .format(tagpath))
                with open(tagpath, 'wb') as f:
                    f.write(packet.share.SerializeToString())
            elif packet.type == comms_pb2.PacketType.RECOVER:
                # TODO: packet.tag - look for tag in local filesystem
                pass
            elif packet.type == comms_pb2.PacketType.RETURN:
                # TODO: packet.share - send share to command processor
                pass
            else:
                logger.warning("Unable to process unknown packet {}.".format(
                    packet.type))

    def _keepalive_broadcaster(self):
        logger.info("Keepalive broadcaster started.")
        ping = comms_pb2.Packet()
        ping.type = comms_pb2.PacketType.IAM
        ping.sender = self.hid
        ping.needs_ack = False
        ping_str = ping.SerializeToString()
        while True:
            time.sleep(HOST_REFRESH_SECONDS)
            self.redis.publish('secaisle:broadcast', ping_str)

    def split_shares(self, tag, plaintext, threshold):
        '''
        :param Server self: The active Server object
        :param bytes plaintext: Plaintext message (in bytes)
        :param str tag: The tag that this message will get filed under
        :param int threshold: Minimum number of shares needed for recreation
        '''
        if threshold > len(self.hosts):
            raise ValueError('Threshold must not be greater than the host count.')
        shares = crypto.split_shares(plaintext, threshold, len(self.hosts))
        i = 0
        for hid in self.hosts.keys():
            packet = comms_pb2.Packet()
            packet.type = comms_pb2.PacketType.STORE
            packet.sender = self.hid
            packet.tag = tag
            packet.share.index = shares[i].index
            packet.share.key_share = shares[i].key_share
            packet.share.ciphertext = shares[i].ciphertext
            packet.share.ciphertext_hash = shares[i].ciphertext_hash
            self.redis.publish('secaisle:host:' + hid,
                               packet.SerializeToString())
            i += 1
        return

    def recover_shares(self, tag):
        '''
        :param Server self: The active Server object
        :param str tag: The tag for the message we want to fetch
        :return: The message if it could be recovered, otherwise None
        :rtype bytes:
        '''
        # TODO: Broadcast RECOVER packet, aggregate RETURN shares
        return None

    def _command_processor(self):
        logger.info("Server is now listening for commands.")
        self.sock.listen(1)
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
                        response.success = True
                        response.host_count = len(self.hosts)
                    elif command.type == comms_pb2.CommandType.SPLIT:
                        try:
                            # Actual plaintext is wrapped in a base64 encoding
                            plaintext = base64.b64decode(command.plaintext.encode())
                            self.split_shares(command.tag,
                                              plaintext,
                                              command.threshold)
                            response.success = True
                        except Exception as e:
                            response.success = False
                            response.payload = str(e)
                    elif command.type == comms_pb2.CommandType.COMBINE:
                        try:
                            message = self.recover_shares(command.tag)
                            # Rewrap plaintext in a base64 encoding
                            response.success = message is not None
                            if response.success:
                                response.payload = base64.b64encode(message).decode()
                            else:
                                response.payload = 'Could not acquire enough shares to reconstruct message.'
                        except Exception as e:
                            response.success = False
                            response.payload = str(e)
                    else:
                        response.success = False
                        response.payload = "Unknown command type {}.".format(command.type)
                    conn.send(response.SerializeToString())
            finally:
                conn.close()

    def run(self):
        threads = []
        threads.append(threading.Thread(target=self._packet_listener,
                                        daemon=True))
        threads.append(threading.Thread(target=self._packet_processor,
                                        daemon=True))
        threads.append(threading.Thread(target=self._keepalive_broadcaster,
                                        daemon=True))
        for thr in threads:
            thr.start()
        self._command_processor()
