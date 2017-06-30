import Queue
import commands


def find_ip(attacker_mac, victim_ip):
    status, ip = commands.getstatusoutput("arp -n | grep -v %s |grep %s | awk '{print $1}'" % (victim_ip, attacker_mac))
    return ip


def arp_oracle(packets_lines_queue, config_dico, decision_queue, prod_evt, evt):
    """
    this function put alert message in queue if it find different mac from same IP between cfg file packet info
    :return: dict() in decision_queue
    """
    spoof_info = dict()
    while True:
        try:
            item = packets_lines_queue.get(timeout=1)
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
                    spoof_info['attacker_ip'] = find_ip(item['mac'], info['ip'])
                    spoof_info['attacker_mac'] = item['mac']
                    spoof_info['victim'] = host
                    spoof_info['victim_ip'] = info['ip']
                    spoof_info['victim_mac'] = info['mac']
                    decision_queue.put(spoof_info)
            else:
                continue
    evt.set()


def sql_oracle(packets_lines_queue, decision_queue, re_list, prod_evt, evt):
    """
    this function put alert message in queue if it find sql injection
    :param packets_lines_queue: 
    :param decision_queue: 
    :param prod_evt: 
    :param evt: 
    :return: dict() in decision_queue
    """
    http_info = dict()
    while True:
        try:
            item = packets_lines_queue.get(timeout=1)
        except Queue.Empty:
            if prod_evt.is_set():
                break
            else:
                continue
        for regex_dict in re_list:
            if not item:
                continue
            if regex_dict.values()[0].findall(item[regex_dict.keys()[0]]):
                item['field'] = regex_dict.keys()[0]
                decision_queue.put(item)
            else:
                continue
    evt.set()