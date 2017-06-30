import pyshark


def arp_parser(filename, arp_lines_queue, interface, evt):
    """
    principal function sniff on file or on network, parse data from this flow and put a dico on the queue
    :return:
    """
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


def sql_parser(filename, sql_lines_queue, interface, evt):
    if filename is not None:
        cap = pyshark.FileCapture(filename, display_filter='http')
    else:
        cap = pyshark.LiveCapture(interface, bpf_filter='http')

    for pkt in cap:
        dico = dict()
        if hasattr(pkt, 'http'):
            if hasattr(pkt.http, "request_method"):
                dico['host'] = pkt.http.host
                dico['method'] = pkt.http.request_method
                dico['uri'] = pkt.http.request_uri
                dico['user_agent'] = pkt.http.user_agent
                dico['ip_src'] = pkt.ip.src
                dico['ip_dst'] = pkt.ip.dst
        sql_lines_queue.put(dico)
    evt.set()