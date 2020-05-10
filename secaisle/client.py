
import socket

import comms_pb2
import sockutil

SOCKET_FILE = '/tmp/secaisle-socket'


class Client:

    def __init__(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(SOCKET_FILE)


    def num_hosts(self):
        command = comms_pb2.Command()
        command.type = comms_pb2.CommandType.NUM_HOSTS
        sockutil.send_msg(self.sock, command.SerializeToString())
        response = comms_pb2.Response()
        response.ParseFromString(sockutil.recv_msg(self.sock))
        if not response.success:
            raise ValueError(response.payload)
        return response.host_count

if __name__ == '__main__':
    print(Client().num_hosts())
