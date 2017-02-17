import Queue
import ethip


def compare_oracle(arp_lines_queue, config_dico, decision_queue, prod_evt, evt):
    """
    this function put alert message in queue if it find different mac from same IP between cfg file packet info
    :return: dict()
    """
    spoof_info = dict()
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
                    spoof_info['attacker_ip'] = ethip.getip(item['mac'], config_dico['network']['ip'])
                    spoof_info['attacker_mac'] = item['mac']
                    spoof_info['victim'] = host
                    spoof_info['victim_ip'] = info['ip']
                    spoof_info['victim_mac'] = info['mac']
                    decision_queue.put(spoof_info)
            else:
                continue
    evt.set()