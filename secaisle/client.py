
import socket
import base64

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
            raise ValueError(response.payload)
        return response

    def num_hosts(self):
        command = comms_pb2.Command()
        command.type = comms_pb2.CommandType.NUM_HOSTS
        sockutil.send_msg(self.sock, command.SerializeToString())
        response = self._validate_response()
        return response.host_count

    def split(self, tag, plaintext, threshold):
        command = comms_pb2.Command()
        command.type = comms_pb2.CommandType.SPLIT
        command.tag = tag
        command.threshold = threshold
        command.plaintext = base64.b64encode(plaintext).decode()
        sockutil.send_msg(self.sock, command.SerializeToString())
        self._validate_response()

    def combine(self, tag):
        command = comms_pb2.Command()
        command.type = comms_pb2.CommandType.COMBINE
        command.tag = tag
        sockutil.send_msg(self.sock, command.SerializeToString())
        response = self._validate_response()
        return base64.b64decode(response.payload.encode())


if __name__ == '__main__':
    client = Client()
    print(client.num_hosts())
    client.split('test', ('a' * 20000).encode(), 1)
    print(client.combine('test'))
