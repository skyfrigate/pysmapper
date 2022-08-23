#! /usr/bin/python3
import binascii
import socket
import sys
import os
import types
import argparse


def check(proto, cipher, rand_bytes, host, port):
    """
    Check if the service defined by the couple (host,port) support the cipher on the protocol version
    It returns a flag describing the result:
        -1 : an error has occurred
        0 : The cipher suite is not supported
        1 : The cipher suite is supported
    :param proto: str
    :param cipher: str
    :param rand_bytes: str
    :param host: str
    :param port: int
    :return: int
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cipher_int = binascii.a2b_hex(cipher)
    try:
        sock.connect((host, port))
    except socket.error as e:
        sock.close()
        sys.stderr.write(e)
        return -1
    sock.send(proto + cipher_int + rand_bytes)
    try:
        msg = sock.recv(1)
    except socket.error:
        sock.close()
        return -1
    if msg == b"\x16":
        return 1
    elif msg == b"\x15":
        return 0
    else:
        sock.recv(8)
        msg = sock.recv(2)
        if msg == b"\x00\x03":
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            return 1
        else:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            return 0


class OutputClass:

    def __init__(self, path, name,cipher_dict):
        self.path = path
        if path is not None:
            self.path = path + os.sep + name + ".csv"
        else:
            self.file = sys.stdout
            self.file.write("\n" + name)

    def __call__(self, content):
        if self.path is not None:
            file = open(self.path, "a")
            file.write(content + "\n")
            file.close()
        else:
            self.file.write("\n" + content)


class VerboseOutputClass:

    def __init__(self, path, name, cipher_dict):
        self.cipher_dict = cipher_dict
        self.path = path
        self.name = name
        if path is not None:
            self.path = path + os.sep + name + ".txt"
            file = open(self.path, "a")
            file.write("Testing ciphers of " + name + " protocol :\n Protocol tested are :")
            for cipher in list(self.cipher_dict.values):
                file.write("\t" + cipher["name"])
            file.close()
        else:
            self.file = sys.stdout
            self.file.write("Testing ciphers of " + name + " protocol :\n Protocol tested are : \n")
            for cipher in list(self.cipher_dict.values()):
                self.file.write("\t" + cipher["name"] + "\n")

    def __call__(self, content):
        if content.startswith("addr"):
            pass
        else:
            if self.path is not None:
                file = open(self.path, "a")
                content.replace("y", "enabled")
                content.replace("n", "disabled")
                list_content = content.split(",")
                file.write("Testing ciphers on : " + list_content[0] + " : ")
                for cipher_index in range(len(self.cipher_dict.values())):
                    file.write("\t" + list(self.cipher_dict.values())[cipher_index]["name"] + " :\t" + list_content[
                        cipher_index + 1])
                file.close()
            else:
                content.replace("y", "enabled")
                content.replace("n", "disabled")
                list_content = content.split(",")
                self.file.write("Testing ciphers on : " + list_content[0] + " : \n")
                for cipher_index in range(len(self.cipher_dict.values())):
                    self.file.write(
                        "\t" + list(self.cipher_dict.values())[cipher_index]["name"] + " :\t" + list_content[
                            cipher_index + 1] + "\n")


class Config:

    def __init__(self, parsed_args):
        self.list_address = parsed_args.iplist
        if parsed_args.input is not None:
            with open(parsed_args.input) as file:
                add_ip_list = file.readlines()
                file.close()
            self.list_address += add_ip_list
        self.input = parsed_args.input
        self.verbose = parsed_args.verbose
        self.output = parsed_args.output
        self.cert = parsed_args.cert
        if parsed_args.port != -1:
            self.port = parsed_args.port
        else:
            self.port = 443
        self.module_path = parsed_args.module_path
        self.update = parsed_args.update


class ModLoader:

    def __init__(self, path):
        if path is None:
            self.path = "config.py"
        else:
            self.path = path

    def load_module(self):
        file = open(self.path)
        content = file.read()
        file.close()
        mod = types.ModuleType("config")
        exec(content, mod.__dict__)
        return mod

    def update_config(self, path):
        """
        Used to update the configuration of the program. Path must be a path to the config update python file. To work
        well, the file need to define 3 var in the file:
            -mode which is a string that define the type of operation, for the moment only "add" is supported
            -cipher_suites which is a dictionary following the same format as the cipher_suites in config.py
            -handshake_pkts which is a dictionary following the same format as handshake_pkts in config.py
        :param path: str
        :return: ModuleType
        """
        file = open(path)
        content = file.read()
        file.close()
        new_conf = {}
        exec(content, new_conf)
        old_conf = self.load_module()
        if new_conf["mode"] == 'add':
            old_conf.handshake_pkts.update(new_conf["handshake_pkts"])
            old_conf.cipher_suites.update(new_conf["cipher_suites"])
        str_conf = "handshake_pkts = " + str(old_conf.handshake_pkts) + "\ncipher_suites = " + str(
            old_conf.cipher_suites) + "\nrand_bytes = " + str(old_conf.rand_bytes)
        file = open(self.path, "w")
        file.write(str_conf)
        file.close()
        return self.load_module()


class Prog:
    """
    Class representing the execution of the program, it is defined as a class for more modularity and usage in other
     circumstances
    """

    def __init__(self, handler, conf):
        """
        Initialise the execution of the program. Argument are a Config instance containing the necessary attributes for
        the program execution and handler is a text handler called to write in file or in the standard output
        :param handler:
        :param conf:
        """
        self.text_handler = handler
        self.conf = conf
        self.mod_loader = ModLoader(self.conf.module_path)
        if self.conf.update is not None:
            self.mod = self.mod_loader.update_config(self.conf.update)
        else:
            self.mod = self.mod_loader.load_module()
        for proto_name, proto_handshake in self.mod.handshake_pkts.items():
            cipher_str_list = ""
            for cipher in self.mod.cipher_suites.keys():
                cipher_str_list += "," + self.mod.cipher_suites[cipher]["name"]
            first_line = "addr" + cipher_str_list
            if handler == VerboseOutputClass or handler == OutputClass:
                if self.conf.verbose:
                    self.text_handler = VerboseOutputClass(self.conf.output, proto_name, self.mod.cipher_suites)
                else:
                    self.text_handler = OutputClass(self.conf.output, proto_name, self.mod.cipher_suites)
            self.text_handler(first_line)
            for address in self.conf.list_address:
                tested_cipher_line = address
                for cipher in self.mod.cipher_suites.keys():
                    result = check(proto_handshake, cipher, self.mod.rand_bytes, address, self.conf.port)
                    if result == -1:
                        tested_cipher_line += ",e"
                    elif result == 0:
                        tested_cipher_line += ",n"
                    else:
                        tested_cipher_line += ",y"
                self.text_handler(tested_cipher_line)

    def text_handler(self, text):
        """
        A callback which will be called while executing the test, can be replaced by any other callable taking the same
        argument to edit a particular format of the data. It will be initialized with the fort line of the document
        containing the tested protocol and then will receive the availability for each address
        :param text: str
        :return: None
        """
        raise NotImplementedError


# Creating the command-line argument parser
parser = argparse.ArgumentParser(description="Test which ciphers are available on an ssl connexion",
                                 epilog="Take a cup of tea after launching this process because it may take prtty\
                                      much time")
parser.add_argument("-i", "--input",
                    help="Indicate the path to a file containing a list of domain name or ip address",
                    dest="input", default=None)
parser.add_argument("iplist", nargs="*", default=[], help="List of the addresses to target. It can be an ipv4\
     address or a domain name")
parser.add_argument("-o", "--output", help="Indicate a path to a file where to write the output in a csv format",
                    dest="output")
parser.add_argument("-v", "--verbose", action="store_true", dest="verbose")
parser.add_argument("-p", "--port", dest="port", type=int, default=-1,
                    help="define the port on which the ssl test must be done")
parser.add_argument("-mp", "--module_path", default=None, dest="module_path",
                    help="Describe the path of the config module, if not specified it will lookup in it's current\
                              directory")
parser.add_argument("-u", "--update", dest="update", default=None, help="Specifying an update for the config of the\
     program, must be followed by a path to a python file containing the update data see documentation in the code for \
                                                                            more information")

if __name__ == "__main__":
    parsed_input = parser.parse_args()
    config = Config(parsed_input)  # Generating the config instance
    Prog(OutputClass, config)  # Starting the execution of the mapping
