import pyshark
import collections


def __rename_port(techno):
    return {
        'mysql': '3306',
        'mssql': '1433',
        'oracle': '1521',
        'postgresql': '5432'
    }.get(techno, None)


def sniffer_function(filename, arp_lines_queue, interface, evt):
    """
    principal function sniff on file or on network, parse data from this flow and put a dico on the queue
    :return:
    """
    sqluser = None
    database = None

    if filename is not None:
        cap = pyshark.FileCapture(filename, display_filter='arp')
    else:
        cap = pyshark.LiveCapture(interface, bpf_filter='arp')

    for pkt in cap:
        dico = dict()
        if hasattr(pkt, 'arp'):
            dico['ip'] = pkt.arp.src_proto_ipv4
            dico['mac'] = pkt.arp.src_hw_mac
            arp_lines_queue.put(dico)
    evt.set()