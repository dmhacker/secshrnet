from abc import ABC, abstractmethod

import redis
from loguru import logger

import uuid
import queue
import threading

from . import comms_pb2


class Host(ABC):

    def __init__(self, channel_prefix, config):
        self.redis = redis.Redis(
            host=config['Redis']['Host'],
            port=int(config['Redis']['Port']),
            password=config['Redis']['Password'])
        self.pubsub = self.redis.pubsub()
        self.received_packets = queue.Queue()
        self.hid = str(uuid.uuid4())
        self.hchannel = channel_prefix + self.hid

    @abstractmethod
    def handle_packet(self, packet):
        pass

    def send_packet(self, channel, packet):
        self.redis.publish(channel, packet.SerializeToString())

    def connected_hosts(self, channel_prefix):
        prefix_len = len(channel_prefix)
        channels = self.redis.pubsub_channels('{}*'.format(channel_prefix))
        return [channel.decode()[prefix_len:] for channel in channels]

    def _packet_listener(self):
        '''
        The packet listener subscribes to the host's private channel on Redis.
        It will poll for packets and forward them to the packet processor.
        '''
        self.pubsub.subscribe(self.hchannel)
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
            self.handle_packet(packet)

    def run(self, block=True):
        '''
        Run the server and potentially block the calling thread.
        '''
        threads = []
        threads.append(threading.Thread(target=self._packet_listener,
                                        daemon=True))
        threads.append(threading.Thread(target=self._packet_processor,
                                        daemon=True))
        for thr in threads:
            thr.start()
        if block:
            for thr in threads:
                thr.join()
