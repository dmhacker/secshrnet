from colorama import Fore, Style

import readline
import getpass

from . import crypto


def read_threshold(args, num_servers):
    try:
        if len(args) < 3:
            threshold = num_servers // 2 + 1
            print("Using a default recovery threshold of {}."
                  .format(threshold))
        else:
            threshold = int(args[2])
            if threshold < 1 or threshold > num_servers:
                print("Recovery threshold should be between 1 and {}."
                      .format(num_servers))
                return None
        return threshold
    except ValueError:
        print("Recovery threshold should be an integer.")
        return None


def read_password(prompt):
    return getpass.getpass(prompt).encode('utf-8')


class SaveCommand:

    def __init__(self, client):
        self.client = client

    def handle(self, args):
        if len(args) < 2 or len(args) > 3:
            print("Usage:", self.usage())
            return
        filepath = args[0]
        tag = args[1]
        num_servers = len(self.client.servers())
        if num_servers == 0:
            print("No servers are online.")
            return
        threshold = read_threshold(args, num_servers)
        if threshold is None:
            return
        password = read_password("Password: ")
        check_password = read_password("Re-enter password: ")
        if password != check_password:
            print("Passwords do not match.")
            return
        with open(filepath, 'rb') as f:
            pt = f.read()
            ct = crypto.encrypt_plaintext(pt, password)
            servers = self.client.split(tag, ct, threshold)
        print("{}File '{}' was split across {} servers.{}"
              .format(Fore.MAGENTA, filepath,
                      len(servers), Style.RESET_ALL))

    def usage(self):
        return "save [FILE] [TAG] {THRESHOLD}"

    def description(self):
        return "Save a file at the specified tag"


class LoadCommand:

    def __init__(self, client):
        self.client = client

    def handle(self, args):
        if len(args) != 2:
            print("Usage:", self.usage())
            return
        tag = args[0]
        filepath = args[1]
        if len(self.client.servers()) == 0:
            print("No servers are online.")
            return
        ct = self.client.recombine(tag)
        password = read_password("Password: ")
        pt = crypto.decrypt_ciphertext(ct, password)
        if pt is None:
            raise crypto.ShareError("Incorrect password.")
        with open(filepath, 'wb') as f:
            f.write(pt)
        print("{}File '{}' was recovered successfully.{}"
              .format(Fore.MAGENTA, filepath, Style.RESET_ALL))

    def usage(self):
        return "load [TAG] [FILE]"

    def description(self):
        return "Load data at a tag into a file"



class ListCommand:

    def __init__(self, client):
        self.client = client

    def handle(self, args):
        if len(self.client.servers()) == 0:
            print("No servers are online.")
            return
        tags = self.client.list_tags()
        if len(tags) == 0:
            print("No tags found.")
        else:
            for (tag, count) in tags:
                print(" - {}{}{} ({} servers)".format(
                    Fore.MAGENTA, tag, Style.RESET_ALL, count))

    def usage(self):
        return "ls"

    def description(self):
        return "List all tags stored in the network"


class ServersCommand:

    def __init__(self, client):
        self.client = client

    def handle(self, args):
        if len(self.client.servers()) == 0:
            print("No servers are online.")
            return
        machines = self.client.server_information()
        for (hid, machine) in machines:
            print("{}{}{}:"
                  .format(Fore.MAGENTA, hid, Style.RESET_ALL))
            print(" | OS = {}".format(machine.os))
            print(" | Hostname = {}".format(machine.name))
            print(" | Free = {:.2f} GB".format(machine.free / 2**30))

    def usage(self):
        return "serv"

    def description(self):
        return "Display all active servers"



class HelpCommand:

    def __init__(self, cli):
        self.cli = cli

    def handle(self, args):
        print("[] = required. {} = optional.")
        for (cmd, obj) in self.cli.commands.items():
            print(" - {}{}{}: {}"
                  .format(Fore.MAGENTA, obj.usage(),
                          Style.RESET_ALL, obj.description()))

    def usage(self):
        return "help"

    def description(self):
        return "Show available commands"


class CommandInterface:

    def __init__(self, client):
        self.client = client
        self.commands = {
            'save': SaveCommand(client),
            'load': LoadCommand(client),
            'ls': ListCommand(client),
            'serv': ServersCommand(client),
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
                if command in self.commands:
                    self.commands[command].handle(args)
                else:
                    print("Unknown command. Use `help` for "
                          "a list of available commands.")
            except crypto.ShareError as e:
                print(str(e))
            except FileNotFoundError as e:
                print(str(e))
            except EOFError:
                print("\nbye")
                break
