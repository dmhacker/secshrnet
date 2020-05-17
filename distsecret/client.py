import socket
import argparse
import sys
import os

import crypto
import comms_pb2
import sockutil
import getpass

SOCKET_FILE = '/tmp/distsecret-0-socket'


class ClientError(Exception):
    pass


class Client:

    def __init__(self, sockfile):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(sockfile)

    def _validate_response(self):
        response = comms_pb2.Response()
        response.ParseFromString(sockutil.recv_msg(self.sock))
        if not response.success:
            raise ClientError(response.error)
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


def read_threshold(num_hosts):
    while True:
        default_threshold = num_hosts // 2 + 1
        threshold_str = input(("Minimum shares needed for "
                               "reconstruction (default = {}): ")
                              .format(default_threshold))
        if threshold_str == "":
            threshold = default_threshold
            break
        try:
            threshold = int(threshold_str)
            if threshold >= 1 and threshold <= num_hosts:
                break
        except ValueError:
            pass
        print("Please enter a number between 1 and {}."
              .format(num_hosts), file=sys.stderr)
    return threshold


def read_password(tag):
    return crypto.hash256(getpass.getpass("Password for tag '{}': "
                                          .format(tag)).encode('utf-8'))


def main():
    parser = argparse.ArgumentParser(
        description='Send commands to a local distsecret hosting server.')
    parser.add_argument('-s', '--split', action='store_true',
                        help='split a file, upload it to the network')
    parser.add_argument('-c', '--combine', action='store_true',
                        help='combine data in the network, store to file')
    parser.add_argument('--socket', default=SOCKET_FILE,
                        help='the socket that the server is running on')
    parser.add_argument('tag', help='unique tag location')
    parser.add_argument('file', help='file to upload from or download to')
    args = parser.parse_args()
    if args.split == args.combine:
        print("Please specify either --split or --combine.", file=sys.stderr)
        sys.exit(1)
        return
    client = Client(args.socket)
    num_hosts = client.num_hosts()
    print("Server is online. {} hosts on the network.".format(num_hosts))
    try:
        if args.split:
            threshold = read_threshold(num_hosts)
            password = read_password(args.tag)
            with open(args.file, 'rb') as f:
                pt = f.read()
                ct = crypto.encrypt_plaintext(pt, password)
                client.split(args.tag, ct, threshold)
            print("Contents of {} uploaded to tag '{}'."
                  .format(args.file, args.tag))
        else:
            ct = client.combine(args.tag)
            password = read_password(args.tag)
            pt = crypto.decrypt_ciphertext(ct, password)
            if pt is None:
                raise ClientError("Incorrect password.")
            with open(args.file, 'wb') as f:
                f.write(pt)
            print("Data for tag '{}' downloaded into {}."
                  .format(args.tag, args.file))
    except ClientError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
