#! /usr/bin/python3
import binascii
import socket
import subprocess
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

    def __init__(self, path, name, cipher_dict):
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
    """
    Class used to make a verbose output
    """

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
    """
    A class representing the specific command line config
    """

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
        if parsed_args.port != -1:
            self.port = parsed_args.port
        else:
            self.port = 443
        self.module_path = parsed_args.module_path
        self.update = parsed_args.update
        self.format = parsed_args.format
        self.on_unsecure_text = parsed_args.on_unsecure_text
        self.on_refused_text = parsed_args.on_refused_text
        self.on_accepted_text = parsed_args.on_accepted_text
        self.unsecure_on_refuse = parsed_args.unsecure_on_refuse
        self.on_unsecure_callback = parsed_args.on_unsecure_callback
        self.on_refused_callback = parsed_args.on_refused_callback
        self.on_accepted_callback = parsed_args.on_accepted_callback


class ModLoader:
    """
    An informal file loader that load a module from a filepath, to get the module variable which work as a standard
    you need to instantiate the class and then call the load_module method which will return the module
    """

    def __init__(self, path):
        if path is None:
            self.path = "config.py"
        else:
            self.path = path

    def load_module(self):
        """
        Load the module from the path given
        :return:
        """
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
        For the moment, the updated file will not be easily readable from a human. When calling the update_config
         method, it will automatically call the load_module method after and return the updated module
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
        str_conf = "handshake_pkts = " + str(old_conf.handshake_pkts) + "\n\ncipher_suites = " + str(
            old_conf.cipher_suites) + "\n\nrand_bytes = " + str(old_conf.rand_bytes) + "\n\naccept_cipher = " + str(
            old_conf.accept_cipher) + "\n\naccept_proto = " + str(old_conf.accept_proto)
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
        :param handler: dict
        :param conf: Config
        """
        self.handler = handler
        self.conf = conf
        if self.conf.verbose:
            self.text_handler = self.handler["verbose"]
        else:
            self.text_handler = self.handler[self.conf.format]
        self.mod_loader = ModLoader(self.conf.module_path)
        if self.conf.update is not None:
            self.mod = self.mod_loader.update_config(self.conf.update)
        else:
            self.mod = self.mod_loader.load_module()

    def __call__(self):
        for proto_name, proto_handshake in self.mod.handshake_pkts.items():
            cipher_str_list = ""
            for cipher in self.mod.cipher_suites.keys():
                cipher_str_list += "," + self.mod.cipher_suites[cipher]["name"]
            first_line = "addr" + cipher_str_list
            self.text_handler(self.conf.output, proto_name, self.mod.cipher_suites)  # instantiating the text_handler
            self.text_handler(first_line)  # start of the writing process
            for address in self.conf.list_address:
                tested_cipher_line = address
                for cipher in self.mod.cipher_suites.keys():
                    result = check(proto_handshake, cipher, self.mod.rand_bytes, address, self.conf.port)
                    str_result = self.result_handler(result, cipher, proto_name)
                    unsecure, reason = self.is_unsecure(cipher, proto_name)
                    if unsecure:
                        if result == 0 and not self.conf.unsecure_on_refuse:
                            pass
                        else:
                            str_result = self.on_unsecure(
                                {"reason": reason, "standard-text": str_result, "proto-name": proto_name,
                                 "cipher-suite": cipher, "address": address})
                    tested_cipher_line += str_result
                self.text_handler(tested_cipher_line)

    def on_unsecure(self, info):
        """
        A method called in case an unsecure cipher is detected, it receives as a parameter a dictionary as info. info
        contains information about which cipher, which version and which machine the unsecure process has occurred.
        It must return a string that works for a csv transformation as the standard-text to be well interpreted by the
        text_handler. If you replace the text formatter, make sure it can handle your result if it does not follow the
        standard one
        :param info: dict
        :return: str
        """
        if self.conf.on_unsecure_callback is not None:
            text = subprocess.run(self.conf.on_unsecure_callback.split(" ") + [info["cipher-suite"]],
                                  info["proto-name"]).stdout
        else:
            text = info["standard-text"] + self.conf.on_unsecure_text
        return text

    def result_handler(self, result, cipher, proto_name):
        """
        A method which is called to analyse the result, it must return a value understandable by the on_unsecure and
        text_handler method, the default one will adapt himself to return a value for the csv.
        :param proto_name: str
        :param cipher: str
        :param result: int
        :return: Any
        """
        if result == -1:
            return ",e"
        elif result == 0:
            if self.conf.on_refused_text is not None:
                return subprocess.run(self.conf.on_refused_callback.split(" ") + [cipher, proto_name],
                                      encoding="utf-8").stdout
            return self.conf.on_refused_text
        else:
            if self.conf.on_accepted_callback is not None:
                return subprocess.run(self.conf.on_accepted_callback.split(" ") + [cipher, proto_name],
                                      encoding="utf-8").stdout
            return self.conf.on_accepted_text

    def is_unsecure(self, cipher_suite, proto):
        if cipher_suite not in self.mod.accept_cipher:
            if proto not in self.mod.accept_proto:
                return True, 3
            else:
                return True, 2
        else:
            if proto not in self.mod.accept_proto:
                return True, 1
            else:
                return False, 0

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
parser = argparse.ArgumentParser(
    description="Test which ciphers are available on an ssl connexion. This utils only support hostname and IPv4\
     addresses",
    epilog="Take a cup of tea after launching this process because it may take prtty\
                                      much time")
parser.add_argument("-i", "--input",
                    help="Indicate the path to a file containing a list of domain name or ip address",
                    dest="input", default=None)
parser.add_argument("iplist", nargs="*", default=[], help="List of the addresses to target. It can be an ipv4\
     address or a domain name")
parser.add_argument("-o", "--output", help="Indicate a path to a file where to write the output in a csv format",
                    dest="output")
parser.add_argument("-f", "--format", default="csv", dest="format", help="Indicate of format in which the output should\
 be done if the -v argument is present, it overrides the -f argument")
parser.add_argument("-v", "--verbose", action="store_true", dest="verbose")
parser.add_argument("-p", "--port", dest="port", type=int, default=-1,
                    help="define the port on which the ssl test must be done")
parser.add_argument("-mp", "--module-path", default=None, dest="module_path",
                    help="Describe the path of the config module, if not specified it will lookup in it's current\
                              directory")
parser.add_argument("-u", "--update", dest="update", default=None, help="Specifying an update for the config of the\
     program, must be followed by a path to a python file containing the update data see documentation in the code for \
                                                                            more information")
parser.add_argument("-oit", "--on-unsecure-text", dest="on_unsecure_text", default="-i", help="Define the text to be\
 printed if a protocol is available but should not be used, it might be added to the on-accepted-text")
parser.add_argument("-oat", "--on-accepted-text", default="y", dest="on_accepted_text",
                    help="define a text to be printed if the protocol is supported by the host")
parser.add_argument("-ort", "--on-refused-text", default="n", dest="on_refused_text",
                    help="Define a text to be printed if the protocol is refused by the host")
parser.add_argument("-oic", "--on-unsecure-callback", dest="on_unsecure_callback",
                    help="describe a command to be called of a shell program if an unsecured cipher is accepted by the\
                     server the callback will receive 2 positional argument cipher and proto_name to help the\
                      analysis or logging")
parser.add_argument("-oac", "--on-accepted-callback", dest="on_accepted_callback",
                    help="Same usage as -oic but if the cipher is accepted")
parser.add_argument("-orc", "--on-refused-callback", dest="on_refused_callback",
                    help="Same usage as -oic but if the cipher is refused")
parser.add_argument("-ior", "--unsecure-on-refuse", dest="unsecure_on_refuse",
                    help="A boolean argument that describe if the unsecure should be called on a refused cipher",
                    default=False)
if __name__ == "__main__":
    handler_dict = {
        "verbose": VerboseOutputClass,
        "csv": OutputClass
    }
    parsed_input = parser.parse_args()
    config = Config(parsed_input)  # Generating the config instance
    Prog(handler_dict, config)()  # running the program is equal to Prog.__init__(handler_dict,config).__call__()
