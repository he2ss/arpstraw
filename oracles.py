import Queue
import re


def blacklist_oracle(arp_lines_queue, config_dico, decision_queue, prod_evt, evt):
    """
    this function print what it get from the queue,
    if the payload match in the query
    :return:
    """

    while True:
        try:
            item = arp_lines_queue.get(timeout=1)
        except Queue.Empty:
            if prod_evt.is_set():
                break
            else:
                continue
        for host, info in config_dico.items():
            if item['ip'] == info['ip']:
                if item['mac'].lower() != info['mac'].lower():
                    decision_queue.put((item['ip'], item['mac'], host, info['ip'], info['mac']))
            else:
                continue
    evt.set()