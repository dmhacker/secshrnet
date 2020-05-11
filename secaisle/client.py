
import socket

import comms_pb2
import sockutil

SOCKET_FILE = '/tmp/secaisle-socket'


class Client:

    def __init__(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(SOCKET_FILE)

    def _validate_response(self):
        response = comms_pb2.Response()
        response.ParseFromString(sockutil.recv_msg(self.sock))
        if not response.success:
            raise ValueError(response.error)
        return response

    def num_hosts(self):
        command = comms_pb2.Command()
        command.type = comms_pb2.CommandType.NUM_HOSTS
        sockutil.send_msg(self.sock, command.SerializeToString())
        response = self._validate_response()
        return response.num_hosts

    def split(self, tag, plaintext, threshold):
        command = comms_pb2.Command()
        command.type = comms_pb2.CommandType.SPLIT
        command.tag = tag
        command.plaintext = plaintext
        command.threshold = threshold
        sockutil.send_msg(self.sock, command.SerializeToString())
        self._validate_response()

    def combine(self, tag):
        command = comms_pb2.Command()
        command.type = comms_pb2.CommandType.COMBINE
        command.tag = tag
        sockutil.send_msg(self.sock, command.SerializeToString())
        response = self._validate_response()
        return response.plaintext


if __name__ == '__main__':
    client = Client()
    print(client.num_hosts())
    client.split('test1', ('a' * 201).encode(), 1)
    client.split('test2', ('z' * 389).encode(), 1)
    for _ in range(2):
        print(client.combine('test1'))
        print(client.combine('test2'))
    print(client.combine('test3'))
