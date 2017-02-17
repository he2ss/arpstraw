import Queue
import ethip
import os


def find_ip(attacker_mac, victim_mac):
    ip = os.system("arp -n | grep -v %s |grep %s | awk '{print $1}'" % victim_mac, attacker_mac)
    return ip


def compare_oracle(arp_lines_queue, config_dico, decision_queue, prod_evt, evt):
    """
    this function put alert message in queue if it find different mac from same IP between cfg file packet info
    :return: dict()
    """
    spoof_info = dict()
    cpt = 0
    while True:
        try:
            item = arp_lines_queue.get(timeout=1)
        except Queue.Empty:
            if prod_evt.is_set():
                break
            else:
                continue
        for host, info in config_dico.items():
            if host == "network":
                continue
            if item['ip'] == info['ip']:
                if item['mac'].lower() != info['mac'].lower():
                    spoof_info['attacker_ip'] = find_ip(item['mac'], info['mac'])
                    spoof_info['attacker_mac'] = item['mac']
                    spoof_info['victim'] = host
                    spoof_info['victim_ip'] = info['ip']
                    spoof_info['victim_mac'] = info['mac']
                    cpt += 1
                    decision_queue.put((spoof_info, cpt))
            else:
                continue
    evt.set()