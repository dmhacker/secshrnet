from expiringdict import ExpiringDict
from queue import Queue

import redis
import uuid
import threading
import logging
import time
import packets_pb2

HOST_REFRESH_SECONDS = 1800
HOST_TTL_SECONDS = 3600


class Server:

    def __init__(self, redis_host, redis_port, redis_password):
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

    def _packet_listener(self):
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
        while True:
            packet = self.received_packets.get()
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
                logging.warn("Packet of type {} not recognized.".format(packet))

    def _keepalive_broadcaster(self):
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
        threads.append(threading.Thread(target=self._packet_listener))
        threads.append(threading.Thread(target=self._packet_processor))
        threads.append(threading.Thread(target=self._keepalive_broadcaster))
        for thr in threads:
            thr.start()
        for thr in threads:
            thr.join()
        # TODO: In the future, listen on a UNIX socket for client commands
