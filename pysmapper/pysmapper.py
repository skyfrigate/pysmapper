#! /usr/bin/python3
import binascii
import datetime
import socket
import subprocess
import sys
import os
import types
import argparse
import abc
import re
import os.path
import urllib.request
import json.encoder
import xml.etree.ElementTree
import xml.dom.minidom


class FileAbstractionClass:
    """
    An abstraction class to a file, it generalise the function used to send an http, ftp request, a standard file or the
    standard output
    """

    def __init__(self, filename=None):
        """
        Initialization of the class, filename must be either a valid URL, a path to a directory or None for the standard
        output
        :param filename:
        """
        self.filename = filename
        if self.filename is not None:
            if ":" in filename:
                self.is_url = True
            else:
                self.is_url = False
                file = open(filename, "a")  # Creating the file if it does not already exist
                file.close()
        else:
            self.is_url = False
        self.str_to_flush = ""
        self.mimetype = None

    def write(self, content, mimetype=None):
        if self.filename is not None:
            if os.path.exists(self.filename):
                file = open(self.filename, "a")
                file.write(content)
                file.close()
            else:
                if mimetype is None:
                    urllib.request.urlopen(urllib.request.Request(self.filename, content))
                else:
                    urllib.request.urlopen(urllib.request.Request(self.filename, content, {"Content-Type": mimetype}))
        else:
            sys.stdout.write(content)

    def bwrite(self, content, mimetype=None):
        """
        Write the content in a buffer instead of directly write it
        :param content:
        :param mimetype:
        :return:
        """
        self.str_to_flush += content
        self.mimetype = mimetype

    def flush(self):
        """
        Write the buffered string, must only be called if bwrite was called earlier
        :return:
        """
        self.write(self.str_to_flush, self.mimetype)
        self.str_to_flush = ""

    def read(self):
        if os.path.exists(self.filename):
            file = open(self.filename, "r")
            text = file.read()
            file.close()
            return text
        elif ":" in self.filename:
            response = urllib.request.urlopen(self.filename)
            text = response.read()
            return text
        else:
            raise FileNotFoundError("Filename is neither a file or an URL")

    def readlines(self):
        """
        Read all the lines and return it as a String, useful to read specific file input
        :return:
        """
        if os.path.exists(self.filename):
            file = open(self.filename, "r")
            text = file.readlines()
            file.close()
            return text
        elif ":" in self.filename:
            response = urllib.request.urlopen(self.filename)
            text = response.readlines()
            return text
        else:
            raise FileNotFoundError("Filename is neither a file or an URL")


class HandlerManager:

    def __init__(self):
        self.dict_handler = {
            "verbose": VerboseOutputClass,
            "csv": CsvOutputClass,
            "openmetrics": OpenMetrics,
            "xml": XMLOutputClass,
            "json": JSONOutputClass
        }

    def __setitem__(self, key, value):
        if issubclass(value, OutputAbstract):
            self.dict_handler[key] = value
        else:
            raise TypeError("value is not a subclass of OutputAbstract")

    def __getitem__(self, item):
        name, sorting, options = self.parse_handler_info(item)
        try:
            return self.dict_handler[name], sorting, options
        except KeyError:
            return self.dict_handler["csv"], sorting, options

    def parse_handler_info(self, item):
        if "-by-" in item:
            name, sorting_and_options = item.split("-by-")
            if "#" in sorting_and_options:
                sorting, options = sorting_and_options.split("#")
                if options == "":
                    options = {}
                else:
                    options = self.parse_options(options)
                return name, sorting, options
            else:
                if sorting_and_options == "":
                    sorting_and_options = None
                return name, sorting_and_options, {}
        else:
            if "#" in item:
                name, options = item.split("#")
                if options == "":
                    options = {}
                else:
                    options = self.parse_options(options)
                return name, None, options
            else:
                return item, None, {}

    @staticmethod
    def parse_options(option_str):
        list_options = option_str.split(",")
        for options_id in range(len(list_options)):
            list_options[options_id] = list_options[options_id].split("=")
        return_dict = {}
        for option_key, option_value in list_options:
            return_dict[option_key] = option_value
        return return_dict


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
    cipher_int = binascii.a2b_hex(cipher)
    try:
        sock = socket.create_connection((host,port))
    except socket.error or TimeoutError as e:
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


class OutputAbstract(abc.ABC):

    @abc.abstractmethod
    def __init__(self, output, cipher_dict, **options):
        pass

    @abc.abstractmethod
    def new_proto(self, proto_name):
        pass

    @abc.abstractmethod
    def new_address(self, proto_name, addr, port):
        pass

    @abc.abstractmethod
    def new_cipher(self, proto_name, addr, cipher, result):
        pass

    @abc.abstractmethod
    def end_of_process(self):
        pass

    @staticmethod
    def select_file(path, name, extension):
        if path is None:
            return FileAbstractionClass()
        elif os.path.exists(path):
            if name is None:
                return FileAbstractionClass(path + os.sep + "output" + extension)
            return FileAbstractionClass(path + os.sep + name + extension)
        else:
            return FileAbstractionClass(path)


class JSONOutputClass(OutputAbstract):

    def __init__(self, path, cipher_dict, **options):
        self.path = path
        self.cipher_dict = cipher_dict
        self.file = self.select_file(path, options.get("name"), ".json")
        self.tree = []

    def new_proto(self, proto_name):
        self.tree.append({"protocol": proto_name, "addresses": []})

    def new_address(self, proto_name, addr, port):
        self.tree[-1]["addresses"].append({"address": addr, "port": port, "ciphers": []})

    def new_cipher(self, proto_name, addr, cipher, result):
        self.tree[-1]["addresses"][-1]["ciphers"].append({"cipher": self.cipher_dict[cipher], "status": result})

    def end_of_process(self):
        self.file.write(json.dumps(self.tree, indent=1), "application/json")


class CsvOutputClass(OutputAbstract):

    def __init__(self, path, cipher_dict, **options):
        self.path = path
        self.cipher_dict = cipher_dict
        self.first_line = "addr,"
        for cipher_id in self.cipher_dict.keys():
            self.first_line += "," + self.cipher_dict[cipher_id]["name"]

    def new_proto(self, proto_name):
        self.file = self.select_file(self.path, proto_name, ".csv")
        if self.path is not None:
            self.file.bwrite(self.first_line, "text/csv")
        else:
            self.file.bwrite(proto_name + "\n" + self.first_line, "text/csv")
        if proto_name != "SSL v2.0":
            self.file.flush()

    def new_address(self, proto_name, addr, port):
        self.file.bwrite("\n" + addr, "text/csv")

    def new_cipher(self, proto_name, addr, cipher, result):
        self.file.bwrite("," + result, "text/csv")

    def end_of_process(self):
        self.file.flush()


class XMLOutputClass(OutputAbstract):

    def __init__(self, output, cipher_dict, **options):
        self.cipher_dict = cipher_dict
        self.path = output
        self.root = xml.etree.ElementTree.Element("result")
        self.file = self.select_file(self.path, options.get("name"), ".xml")
        self.last_proto = None
        self.last_address = None

    def new_proto(self, proto_name):
        self.last_proto = xml.etree.ElementTree.Element("protocol", name=proto_name)
        self.root.append(self.last_proto)

    def new_address(self, proto_name, addr, port):
        self.last_address = xml.etree.ElementTree.Element("address", name=addr, port=port)
        self.last_proto.append(self.last_address)

    def new_cipher(self, proto_name, addr, cipher, result):
        if "-u" in result:
            self.last_address.append(
                xml.etree.ElementTree.Element("cipher", name=self.cipher_dict[cipher]["name"], status=result,
                                              unsecure="true"))
        else:
            self.last_address.append(
                xml.etree.ElementTree.Element("cipher", name=self.cipher_dict[cipher]["name"], status=result,
                                              unsecure="false"))

    def end_of_process(self):
        xml_minidom = xml.dom.minidom.parseString(
            xml.etree.ElementTree.tostring(self.root, "unicode", xml_declaration=True))
        self.file.write(xml_minidom.toprettyxml(), "application/xml")


class VerboseOutputClass(OutputAbstract):
    """
    Class used to make a verbose output
    """

    def __init__(self, output, cipher_dict, **options):
        print("instantiated")
        self.cipher_dict = cipher_dict
        self.path = output
        if output is None:
            self.frequent_flush = True
        self.file = self.select_file(self.path, options.get("name"), ".txt")

    def new_proto(self, proto_name):
        self.file.bwrite("Testing ciphers of " + proto_name + " protocol :\n Number of tested cipher is : \n" + str(
            len(self.cipher_dict)) + "\n", "text/plain")
        if self.frequent_flush:
            self.file.flush()

    def new_address(self, proto_name, addr, port):
        self.file.bwrite("\tTesting cipher on " + addr + " :\n", "text/plain")
        if self.frequent_flush:
            self.file.flush()

    def new_cipher(self, proto_name, addr, cipher, result):
        if "-u" in result:
            self.file.bwrite("\tTesting " + self.cipher_dict[cipher]["name"] + " cipher suite :\n\t\tCipher supported - Warning unsecure\
                 cipher\n", "text/plain")
        elif result == "y":
            self.file.bwrite(
                "\tTesting " + self.cipher_dict[cipher]["name"] + " cipher suite :\n\t\tCipher supported\n",
                "text/plain")
        elif result == "n":
            self.file.bwrite(
                "\tTesting " + self.cipher_dict[cipher]["name"] + " cipher suite :\n\t\tCipher unsupported\n",
                "text/plain")
        else:
            self.file.bwrite("\tTesting " + self.cipher_dict[cipher]["name"] + " cipher suite :\n\t\t Error\n",
                             "text/plain")
        if self.frequent_flush:
            self.file.flush()

    def end_of_process(self):
        self.file.flush()


class OpenMetrics(OutputAbstract):
    format_regex = r'"(?=:)|(?<=, )"|(?<={)"'

    def __init__(self, output, cipher_dict, **options):
        if options.get("sorting") != "address":
            raise NotImplementedError("Openmetrics doesn't support any sorting else than by address")
        self.file = self.select_file(output, options.get("name"), ".txt")
        self.per_address = {}
        self.cipher_dict = cipher_dict
        self.options = options

    def new_address(self, proto_name, addr, port):
        try:
            self.per_address[addr][proto_name] = []
        except KeyError:
            self.per_address[addr] = {proto_name:[]}

    def new_proto(self, proto_name):
        pass

    def new_cipher(self, proto_name, addr, cipher, result):
        self.per_address[addr][proto_name].append(
            {"protocol-version": proto_name, "name": addr, "cipher": self.cipher_dict[cipher]["name"],
             "status": result})

    def end_of_process(self):
        if self.options.get("one-family") is not None:
            if self.options.get("one-family").lower() == "true":
                if self.options.get("custom-name") is not None:
                    name = self.options["custom-name"]
                else:
                    name = "cypher_scan"
                self.file.bwrite("#TYPE " + name + " info\n","application/openmetrics-text; version=1.0.0; charset=utf-8")
                self.file.bwrite("#HELP " + name + " Analysis of the ciphers\n",
                                 "application/openmetrics-text; version=1.0.0; charset=utf-8t")
                for address in self.per_address.keys():
                    for proto_name in self.per_address[address].keys():
                        for info_dict in self.per_address[address][proto_name]:
                            str_to_write = name + "_info" + self.dictionary_to_metrics(info_dict, address) + " 1\n"
                            self.file.bwrite(str_to_write, "application/openmetrics-text; version=1.0.0; charset=utf-8")
        else:
            for address in self.per_address.keys():
                for proto_name in self.per_address[address].keys():
                    self.file.bwrite("#TYPE " + address + " info\n",
                             "application/openmetrics-text; version=1.0.0; charset=utf-8")
                    self.file.bwrite("#HELP " + address + " Analysis of the " + address + "'s ciphers\n",
                             "application/openmetrics-text; version=1.0.0; charset=utf-8t")
                    for info_dict in self.per_address[address][proto_name]:
                        str_to_write = address + "_info" + self.dictionary_to_metrics(info_dict, address) + " 1\n"
                        self.file.bwrite(str_to_write, "application/openmetrics-text; version=1.0.0; charset=utf-8")
                    self.file.bwrite("\n", "application/openmetrics-text; version=1.0.0; charset=utf-8")
        self.file.flush()

    def dictionary_to_metrics(self, dictionary, addr):
        str_to_return = str(dictionary)
        str_to_return = str_to_return.replace("'", "\"")
        str_to_return = re.sub(self.format_regex, "", str_to_return)
        str_to_return = str_to_return.replace(": ", "=")
        return str_to_return


class Config:
    """
    A class representing the specific command line config
    """

    def __init__(self, parsed_args):
        self.list_address = parsed_args.iplist
        if parsed_args.input is not None:
            file = FileAbstractionClass(parsed_args.input)
            add_ip_list = []
            for item_list in file.readlines():
                add_ip_list.append(item_list.rstrip("\n\r"))
            self.list_address += add_ip_list
        self.input = parsed_args.input
        self.verbose = parsed_args.verbose
        self.output = parsed_args.output
        if parsed_args.port is not None:
            self.port = parsed_args.port
        else:
            if parsed_args.port_detection is not None:
                self.port_detection = parsed_args.port_detection
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

    def detect_port(self, addr, port_list):
        if self.port_detection:
            for port in port_list:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sock.connect((addr, port))
                except ConnectionRefusedError:
                    pass
                else:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    return port
            raise ConnectionError("Not port available on " + addr)
        else:
            return self.port


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
        str_conf = "# Last edited on" + str(datetime.datetime.today()) + "\nhandshake_pkts = " + str(
            old_conf.handshake_pkts) + "\n\ncipher_suites = " + str(
            old_conf.cipher_suites) + "\n\nrand_bytes = " + str(old_conf.rand_bytes) + "\n\naccept_cipher = " + str(
            old_conf.accept_cipher) + "\n\naccept_proto = " + str(
            old_conf.accept_proto) + "\n\npotential_ports = " + str(
            old_conf.potential_ports)
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
        if handler.__class__.__name__ != "HandlerManager":
            raise TypeError("Handler must be an instance of HandlerManager")
        self.handler = handler
        self.conf = conf
        if self.conf.verbose:
            self.text_handler, self.sorting, self.options = self.handler["verbose"]
        else:
            self.text_handler, self.sorting, self.options = self.handler[self.conf.format]
        self.mod_loader = ModLoader(self.conf.module_path)
        if self.conf.update is not None:
            self.mod = self.mod_loader.update_config(self.conf.update)
        else:
            self.mod = self.mod_loader.load_module()

    def __call__(self):
        self.text_handler = self.text_handler(self.conf.output, self.mod.cipher_suites, sorting=self.sorting,
                                              **self.options)  # instantiating the text_handler
        for proto_name, proto_handshake in self.mod.handshake_pkts.items():
            self.text_handler.new_proto(proto_name)  # start of the writing process
            for address in self.conf.list_address:
                self.text_handler.new_address(proto_name, address, self.conf)
                self.port = self.conf.detect_port(address, self.mod.potential_ports)
                for cipher in self.mod.cipher_suites.keys():
                    result = check(proto_handshake, cipher, self.mod.rand_bytes, address, self.port)
                    str_result = self.result_handler(result, cipher, proto_name)
                    unsecure, reason = self.is_unsecure(self.mod.cipher_suites[cipher]["name"], proto_name)
                    if unsecure:
                        if not (result <= 0 and not self.conf.unsecure_on_refuse):
                            str_result = self.on_unsecure(
                                {"reason": reason, "standard-text": str_result, "proto-name": proto_name,
                                 "cipher-suite": cipher, "address": address, "port": self.port})
                    self.text_handler.new_cipher(proto_name, address, cipher, str_result)
        self.text_handler.end_of_process()

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
            return "e"
        elif result == 0:
            if self.conf.on_refused_callback is not None:
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
                    dest="input")
parser.add_argument("iplist", nargs="*", default=[], help="List of the addresses to target. It can be an ipv4\
     address or a domain name")
parser.add_argument("-o", "--output", help="Indicate a path to a file where to write the output in a csv format",
                    dest="output")
parser.add_argument("-f", "--format", default="csv", dest="format", help="Indicate of format in which the output should\
 be done if the -v argument is present, it overrides the -f argument")
parser.add_argument("-v", "--verbose", action="store_true", dest="verbose")
parser.add_argument("-p", "--port", dest="port", type=int,
                    help="define the port on which the ssl test must be done")
parser.add_argument("-mp", "--module-path", dest="module_path",
                    help="Describe the path of the config module, if not specified it will lookup in it's current\
                              directory")
parser.add_argument("-u", "--update", dest="update", help="Specifying an update for the config of the\
     program, must be followed by a path to a python file containing the update data see documentation in the code for \
                                                                            more information")
parser.add_argument("-ount", "--on-unsecure-text", dest="on_unsecure_text", default="-u", help="Define the text to be\
 printed if a protocol is available but should not be used, it might be added to the on-accepted-text")
parser.add_argument("-oat", "--on-accepted-text", default="y", dest="on_accepted_text",
                    help="define a text to be printed if the protocol is supported by the host")
parser.add_argument("-ort", "--on-refused-text", default="n", dest="on_refused_text",
                    help="Define a text to be printed if the protocol is refused by the host")
parser.add_argument("-ounc", "--on-unsecure-callback", dest="on_unsecure_callback",
                    help="describe a command to be called of a shell program if an unsecured cipher is accepted by the\
                     server the callback will receive 2 positional argument cipher and proto_name to help the\
                      analysis or logging")
parser.add_argument("-oac", "--on-accepted-callback", dest="on_accepted_callback",
                    help="Same usage as -oic but if the cipher is accepted")
parser.add_argument("-orc", "--on-refused-callback", dest="on_refused_callback",
                    help="Same usage as -oic but if the cipher is refused")
parser.add_argument("-uor", "--unsecure-on-refuse", dest="unsecure_on_refuse",
                    help="A boolean argument that describe if the unsecure should be called on a refused cipher",
                    default=False)
parser.add_argument("-pd", "--port-detection", action="store_true", dest="port_detection", help="If specified will try to\
                             find an open TLS/SSL port on the address. If -p is specified -pd will ve ignored")
if __name__ == "__main__":
    parsed_input = parser.parse_args()
    config = Config(parsed_input)  # Generating the config instance
    Prog(HandlerManager(), config)()  # running the program is equal to Prog.__init__(handler_dict,config).__call__()
