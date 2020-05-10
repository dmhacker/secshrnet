from loguru import logger
from collections import Counter

import redis
import pathlib
import uuid
import threading
import time
import os
import socket
import base64
import queue

import crypto
import sockutil
import comms_pb2

RECOVER_TIMEOUT_SECONDS = 30
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
        self.redis = redis.Redis(
            host=redis_host,
            port=redis_port,
            password=redis_password)
        self.pubsub = self.redis.pubsub()
        self.hid = str(uuid.uuid4())
        self.received_packets = queue.Queue()
        self.return_packets = queue.Queue()
        logger.add("logs/secaisle_{}.log".format(self.hid))
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
        :param bytes plaintext: Plaintext message (in bytes)
        :param str tag: The tag that this message will get filed under
        :param int threshold: Minimum number of shares needed for recreation
        '''
        hkeys = self.hosts()
        if threshold > len(hkeys):
            raise ValueError('Threshold must not be greater than \
                             the host count.')
        shares = crypto.split_shares(plaintext, threshold, len(hkeys))
        for i, hid in enumerate(hkeys):
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

    def combine_shares(self, tag):
        '''
        :param Server self: The active Server object
        :param str tag: The tag for the message we want to fetch
        :return: The message if it could be recovered, otherwise None
        :rtype bytes:
        '''
        packet = comms_pb2.Packet()
        packet.type = comms_pb2.PacketType.RECOVER
        packet.sender = self.hid
        packet.tag = tag
        self.redis.publish('secaisle:broadcast', packet.SerializeToString())
        hkeys = self.hosts()
        timestamp = time.time() + RECOVER_TIMEOUT_SECONDS
        shares = []
        while True:
            try:
                timeout = timestamp - time.time()
                if timeout <= 0:
                    break
                packet = self.return_packets.get(timeout=timeout)
                if packet.sender in hkeys:
                    shares.append(packet.share)
                    hkeys.remove(packet.sender)
                    if len(hkeys) == 0:
                        break
            except queue.Empty:
                break
        if not shares:
            return None
        hashes = [share.ciphertext_hash for share in shares]
        max_hash, _ = Counter(hashes).most_common(1)[0]
        majority_shares = [share for share in shares if share.ciphertext_hash == max_hash]
        if not majority_shares:
            return None
        return crypto.combine_shares(majority_shares)

    def _packet_listener(self):
        '''
        The packet listener subscribes to two channels on Redis, the broadcast
        channel and the host's private channel. It will continually poll for
        packets and forward them to the packet processor.

        Processing is not done on the packet listener's thread. This is because
        the listener can miss messages if it is not continuously polling.
        Redis's pub/sub architecture is ephemeral, meaning that it doesn't
        persist messages. Thus, if a message is missed, the listener can
        never get it back nor even know about it.
        '''
        self.pubsub.subscribe('secaisle:broadcast')
        self.pubsub.subscribe('secaisle:host:' + self.hid)
        for message in self.pubsub.listen():
            if message['type'] == 'message':
                packet = comms_pb2.Packet()
                try:
                    packet.ParseFromString(message['data'])
                    self.received_packets.put(packet)
                except Exception:
                    logger.warn("Unparsable packet on channel {}."
                                .format(message['channel']))

    def _packet_processor(self):
        '''
        The packet processor is responsible for dealing with incoming
        packets. It will wait on a blocking queue for packets to be
        inserted from the packet listener. Every time a packet arrives,
        it will be handled individually and in-order. This may entail
        response packets being broadcasted back.
        '''
        while True:
            packet = self.received_packets.get()
            if packet.type == comms_pb2.PacketType.STORE:
                logger.info("Saving share for tag '{}' from host {}."
                            .format(packet.tag, packet.sender))
                tagpath = os.path.join(SHARE_DIRECTORY, packet.tag)
                if os.path.exists(tagpath):
                    logger.warning('{} is being overwritten.'
                                   .format(tagpath))
                with open(tagpath, 'wb') as f:
                    f.write(packet.share.SerializeToString())
            elif packet.type == comms_pb2.PacketType.RECOVER:
                logger.info("Sending share for tag '{}' to host {}."
                            .format(packet.tag, packet.sender))
                tagpath = os.path.join(SHARE_DIRECTORY, packet.tag)
                if os.path.exists(tagpath):
                    with open(tagpath, 'rb') as f:
                        response = comms_pb2.Packet()
                        response.type = comms_pb2.PacketType.RETURN
                        response.sender = self.hid
                        response.share.ParseFromString(f.read())
                        self.redis.publish('secaisle:host:' + packet.sender,
                                           response.SerializeToString())
            elif packet.type == comms_pb2.PacketType.RETURN:
                logger.info("Got a share from host {}."
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
                        logger.info("Processing NUM_HOSTS command.")
                        response.success = True
                        response.host_count = len(self.hosts())
                    elif command.type == comms_pb2.CommandType.SPLIT:
                        logger.info("Processing SPLIT command for tag '{}'."
                                    .format(command.tag))
                        try:
                            # Received plaintext must be base64-decoded
                            plaintext = base64.b64decode(
                                command.plaintext.encode())
                            self.split_plaintext(command.tag,
                                                 plaintext,
                                                 command.threshold)
                            response.success = True
                        except Exception as e:
                            response.success = False
                            response.payload = str(e)
                    elif command.type == comms_pb2.CommandType.COMBINE:
                        logger.info("Processing COMBINE command for tag '{}'."
                                    .format(command.tag))
                        try:
                            message = self.combine_shares(command.tag)
                            response.success = message is not None
                            if response.success:
                                # Outgoing plaintext must be base64-encoded
                                response.payload = base64.b64encode(
                                    message).decode()
                            else:
                                response.payload = "Could not acquire enough \
                                    shares to reconstruct message."
                        except Exception as e:
                            response.success = False
                            response.payload = str(e)
                    else:
                        response.success = False
                        response.payload = "Unknown command \
                            type {}.".format(command.type)
                    sockutil.send_msg(conn, response.SerializeToString())
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


if __name__ == '__main__':
    Server(os.environ['REDIS_URL'],
           int(os.environ['REDIS_PORT']),
           os.environ['REDIS_DATABASE']).run()
