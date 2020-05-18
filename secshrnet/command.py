from colorama import Fore, Style

import readline
import getpass

from . import crypto


def read_threshold(num_hosts):
    while True:
        default_threshold = num_hosts // 2 + 1
        prompt = "{}Minimum shares (default = {}){}: ".format(
            Fore.YELLOW, num_hosts, Style.RESET_ALL)
        threshold_str = input(prompt)
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
              .format(num_hosts))
    return threshold


def read_password():
    prompt = "{}Password{}: ".format(Fore.YELLOW, Style.RESET_ALL)
    return crypto.hash256(getpass.getpass(prompt).encode('utf-8'))


class CommandInterface:

    def __init__(self, client):
        self.client = client
        self.commands = {
            'split': self.split_command,
            'combine': self.combine_command,
            'tags': self.tags_command
        }
        readline.parse_and_bind('tab: complete')
        readline.parse_and_bind('set editing-mode vi')

    def split_command(self, command, args):
        if len(args) < 3:
            print("Usage: split <TAG> <FILE>")
            return
        tag = args[1]
        filepath = ' '.join(args[2:])
        threshold = read_threshold(num_servers)
        password = read_password()
        with open(filepath, 'rb') as f:
            pt = f.read()
            ct = crypto.encrypt_plaintext(pt, password)
            self.client.split(tag, ct, threshold)
        print("Contents of {} uploaded to tag '{}'."
            .format(filepath, tag))

    def combine_command(self, command, args):
        if len(args) < 3:
            print("Usage: combine <TAG> <FILE>")
            return
        tag = args[1]
        filepath = ' '.join(args[2:])
        ct = self.client.combine(tag)
        password = read_password()
        pt = crypto.decrypt_ciphertext(ct, password)
        if pt is None:
            raise crypto.ShareError("Incorrect password.")
        with open(filepath, 'wb') as f:
            f.write(pt)
        print("Data for tag '{}' downloaded into {}."
            .format(tag, filepath))

    def tags_command(self, command, args):
        tags = self.client.list_tags()
        if len(tags) == 0:
            print("No tags available on network.")
        else:
            for (tag, count) in tags:
                print(" - {} ({} servers)".format(tag, count))

    def parse_input(self, full_command, num_servers):
        if num_servers == 0:
            print("No active servers on the network.")
            return
        args = full_command.split(' ')
        command = args[0].lower()
        args = args[1:]
        if command in self.commands:
            self.commands[command](command, args)
        else:
            print("Unable to interpret command.")

    def run(self):
        while True:
            try:
                num_servers = len(self.client.servers())
                prompt = "{}{}{} servers{}> ".format(
                    Style.BRIGHT,
                    Fore.RED if num_servers == 0 else Fore.GREEN,
                    num_servers, Style.RESET_ALL)
                self.parse_input(input(prompt), num_servers)
            except crypto.ShareError as e:
                print(str(e))
            except FileNotFoundError as e:
                print(str(e))
            except EOFError:
                print("\nbye")
                break
