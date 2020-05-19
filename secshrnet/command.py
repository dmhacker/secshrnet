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


class SplitCommand:

    def __init__(self, client):
        self.client = client

    def handle(self, args):
        if len(args) < 2:
            print("Usage:", self.usage())
            return
        tag = args[0]
        filepath = ' '.join(args[1:])
        threshold = read_threshold(len(self.client.servers()))
        password = read_password()
        with open(filepath, 'rb') as f:
            pt = f.read()
            ct = crypto.encrypt_plaintext(pt, password)
            self.client.split(tag, ct, threshold)
        print("Contents of {} uploaded to tag '{}'."
            .format(filepath, tag))

    def usage(self):
        return "split <TAG> <FILE>"

    def description(self):
        return "Store a file at the specified tag"


class CombineCommand:

    def __init__(self, client):
        self.client = client

    def handle(self, args):
        if len(args) < 2:
            print("Usage:", self.usage())
            return
        tag = args[0]
        filepath = ' '.join(args[1:])
        ct = self.client.combine(tag)
        password = read_password()
        pt = crypto.decrypt_ciphertext(ct, password)
        if pt is None:
            raise crypto.ShareError("Incorrect password.")
        with open(filepath, 'wb') as f:
            f.write(pt)
        print("Data for tag '{}' downloaded into {}."
            .format(tag, filepath))

    def usage(self):
        return "combine <TAG> <FILE>"

    def description(self):
        return "Recreate the file stored at a tag"



class TagsCommand:

    def __init__(self, client):
        self.client = client

    def handle(self, args):
        tags = self.client.list_tags()
        if len(tags) == 0:
            print("No tags available on network.")
        else:
            for (tag, count) in tags:
                print(" - {}{}{} ({} servers)".format(Fore.MAGENTA, tag, Style.RESET_ALL, count))

    def usage(self):
        return "tags"

    def description(self):
        return "Print all tags stored in the network"


class HelpCommand:

    def __init__(self, cli):
        self.cli = cli

    def handle(self, args):
        for (cmd, obj) in self.cli.commands.items():
            print(" - {}{}{}: {}".format(Fore.MAGENTA, obj.usage(), Style.RESET_ALL, obj.description()))

    def usage(self):
        return "help"

    def description(self):
        return "Show all available commands"


class CommandInterface:

    def __init__(self, client):
        self.client = client
        self.commands = {
            'split': SplitCommand(client),
            'combine': CombineCommand(client),
            'tags': TagsCommand(client),
            'help': HelpCommand(self)
        }
        readline.parse_and_bind('tab: complete')
        readline.parse_and_bind('set editing-mode vi')

    def run(self):
        while True:
            try:
                num_servers = len(self.client.servers())
                prompt = "{}{}{} servers{}> ".format(
                    Style.BRIGHT,
                    Fore.RED if num_servers == 0 else Fore.GREEN,
                    num_servers, Style.RESET_ALL)
                full_command = input(prompt)
                args = full_command.split(' ')
                command = args[0].lower()
                args = args[1:]
                num_servers = len(self.client.servers())
                if num_servers == 0:
                    print("No servers available on network.")
                elif command in self.commands:
                    self.commands[command].handle(args)
                else:
                    print("Unable to interpret command.")
            except crypto.ShareError as e:
                print(str(e))
            except FileNotFoundError as e:
                print(str(e))
            except EOFError:
                print("\nbye")
                break
