import socket
import argparse
import sys

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


def main():
    parser = argparse.ArgumentParser(
        description='Send commands to a local secaisle hosting server.')
    parser.add_argument('-s', '--split', action='store_true',
                        help='split a file, upload it to the network')
    parser.add_argument('-c', '--combine', action='store_true',
                        help='combine data in the network, store to file')
    parser.add_argument('tag', help='unique tag location')
    parser.add_argument('file', help='file to upload from or download to')
    args = parser.parse_args()
    if args.split == args.combine:
        print("Please specify either --split or --combine.", file=sys.stderr)
        sys.exit(1)
        return
    client = Client()
    num_hosts = client.num_hosts()
    print("Server is online. {} hosts on the network".format(num_hosts))
    if args.split:
        pass
    else:
        pass


if __name__ == '__main__':
    main()
