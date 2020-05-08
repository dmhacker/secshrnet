from expiringdict import ExpiringDict
from queue import Queue
from loguru import logger

import pathlib
import redis
import uuid
import threading
import time
import os
import socket

import packets_pb2

HOST_REFRESH_SECONDS = 1800
HOST_TTL_SECONDS = 3600
SOCKET_FILE = '{}/secaisle/socket'.format(os.environ['XDG_RUNTIME_DIR'])
SHARE_DIRECTORY = '{}/.secaisle/shares'.format(os.environ['HOME'])


class Server:

    def __init__(self, redis_host, redis_port, redis_password):
        pathlib.Path(SHARE_DIRECTORY).mkdir(parents=True, exist_ok=True)
        try:
            os.unlink(SOCKET_FILE)
        except OSError:
            if os.path.exists(SOCKET_FILE):
                raise ValueError("Socket address {} is already in use.")
        pathlib.Path(SOCKET_FILE).parent.mkdir(parents=True, exist_ok=True)
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
        ping = packets_pb2.Packet()
        ping.type = packets_pb2.PacketType.IAM
        ping.sender = self.hid
        ping.needs_ack = True
        self.redis.publish('secaisle:broadcast', ping.SerializeToString())
        for message in self.pubsub.listen():
            if message['type'] == 'message':
                packet = packets_pb2.Packet()
                packet.ParseFromString(message['data'])
                self.received_packets.put(packet)

    def _packet_processor(self):
        logger.info("Packet processor started.")
        while True:
            packet = self.received_packets.get()
            logger.info("Received packet {} from host {}.".format(
                packet.type, packet.sender))
            if packet.type == packets_pb2.PacketType.IAM:
                self.hosts[packet.sender] = True
                if packet.needs_ack:
                    pong = packets_pb2.Packet()
                    pong.type = packets_pb2.PacketType.IAM
                    pong.sender = self.hid
                    pong.needs_ack = False
                    self.redis.publish('secaisle:host:' + packet.sender,
                                       pong.SerializeToString())
            elif packet.type == packets_pb2.PacketType.STORE:
                pass
            elif packet.type == packets_pb2.PacketType.RECOVER:
                pass
            elif packet.type == packets_pb2.PacketType.RETURN:
                pass
            else:
                logger.warn("Unable to process unknown packet {}.".format(
                    packet.type))

    def _keepalive_broadcaster(self):
        logger.info("Keepalive broadcaster started.")
        ping = packets_pb2.Packet()
        ping.type = packets_pb2.PacketType.IAM
        ping.sender = self.hid
        ping.needs_ack = False
        ping_str = ping.SerializeToString()
        while True:
            time.sleep(HOST_REFRESH_SECONDS)
            self.redis.publish('secaisle:broadcast', ping_str)

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

        logger.info("Server is now listening on its socket.")
        self.sock.listen(1)
        while True:
            conn, client_addr = self.sock.accept()
            try:
                data = conn.recv(1024)
                print(data)
            finally:
                conn.close()
