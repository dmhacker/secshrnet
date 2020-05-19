from abc import ABC, abstractmethod

import redis
from loguru import logger

import uuid
import queue
import threading

from . import network_pb2


class Host(ABC):

    def __init__(self, config, channel_prefix, channel_broadcast=None):
        '''
        :param str channel_prefix: Prefix to be prepended to our channel name
        :param configparser.Config config: Redis configuration file
        '''
        self.redis = redis.Redis(
            host=config['Redis']['Host'],
            port=int(config['Redis']['Port']),
            password=config['Redis']['Password'])
        self.pubsub = self.redis.pubsub()
        self.received_packets = queue.Queue()
        self.hid = str(uuid.uuid4())
        self.hchannel = channel_prefix + self.hid
        self.bchannel = channel_broadcast

    @abstractmethod
    def handle_packet(self, packet):
        '''
        Determines how an incoming packet is processed.
        Implemented by subclasses.
        :param network_pb2.Packet packet: An incoming packet
        '''
        pass

    def send_packet(self, channel, packet):
        '''
        Sends a protobuf packet to the given Redis channel.
        :param str channel: The channel name
        :param network_pb2.Packet packet: An outgoing packet
        '''
        self.redis.publish(channel, packet.SerializeToString())

    def connected_hosts(self, channel_prefix):
        '''
        Returns a list of hosts that subscribed to channels
        matching the given prefix. Segmenting by channel prefix
        allows us to identify servers and clients separately.
        :param str channel_prefix: The channel prefix to match against
        :return: A list of host IDs
        :rtype: [str]
        '''
        prefix_len = len(channel_prefix)
        channels = self.redis.pubsub_channels('{}*'.format(channel_prefix))
        return [channel.decode()[prefix_len:] for channel in channels]

    def _packet_listener(self):
        '''
        The packet listener subscribes to the host's private channel on Redis.
        It will poll for packets and forward them to the packet processor.
        '''
        self.pubsub.subscribe(self.hchannel)
        if self.bchannel:
            self.pubsub.subscribe(self.bchannel)
        logger.info("Packet listener thread is now online.")
        for message in self.pubsub.listen():
            if message['type'] == 'message':
                packet = network_pb2.Packet()
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
            self.handle_packet(packet)

    def run(self):
        '''
        Run the host threads asynchronously.
        '''
        threads = []
        threads.append(threading.Thread(target=self._packet_listener,
                                        daemon=True))
        threads.append(threading.Thread(target=self._packet_processor,
                                        daemon=True))
        for thr in threads:
            thr.start()
