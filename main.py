import argparse
import logging
import Queue
import collections
import ConfigParser
import os
import gi
gi.require_version('Notify', '0.7')
from gi.repository import Notify
from multiprocessing import Process, Queue as MPQueue, Event

import netifaces

from sniffer import sniffer_function
from oracle import compare_oracle


if os.getuid() != 0:
    exit("Error: root permission is required to run this program !")

FORMAT = "%(asctime)-15s %(message)s"
logging.basicConfig(filename='arpstraw.log', filemode='a', level=logging.INFO, format=FORMAT)


parser = argparse.ArgumentParser(description='ARP Straw')
parser.add_argument('-f', '--file', default=None, type=argparse.FileType('r'), help="Specify file to analyse")
parser.add_argument('-i', '--interface', default=None, type=str, help="Specify interface eth0|lo|eth1 ...")
args = parser.parse_args()

config = ConfigParser.ConfigParser()
if os.path.exists('arpstraw.cfg'):
    config.read('arpstraw.cfg')
    conf_dico = collections.defaultdict(lambda: collections.defaultdict())
    for section in config.sections():
        for item in config.options(section):
            conf_dico[section][item] = config.get(section, item)
else:
    exit("Error : can't open arpstraw.cfg file !")
    logging.info("Error : can't open arpstraw.cfg file !")


from pyshark.packet import layer


class LayerFieldsContainer(layer.LayerFieldsContainer):
    def __new__(cls, main_field, *args, **kwargs):
        if hasattr(main_field, 'get_default_value'):
            obj = str.__new__(cls, main_field.get_default_value(), *args, **kwargs)
        else:
            obj = str.__new__(cls, main_field, *args, **kwargs)
        obj.fields = [main_field]
        return obj
layer.LayerFieldsContainer = LayerFieldsContainer


def notif(msg):
    Notify.init("ArpStraw")
    notice = Notify.Notification.new("Critical !", msg)
    notice.set_urgency(2)
    #Adding callback feature but not work because of reinitialisation of the object
    #Need to check if we can register objects in list to recall them.
    notice.add_action(
        "action_click",
        "Find attacker IP and flood him",
        attack,
        "Test"
    )
    notice.show()
    logging.info(msg)


def attack(msg):
    print(msg)


def main():

    if args.file is None:
        if args.interface is None:
            parser.error('required parameters : -i/--interface INTERFACE')
        else:
            interfaces = netifaces.interfaces()
            if args.interface not in interfaces:
                print('ERROR: please specify a valid interface : \n%s' % ' | '.join(interfaces))
                return

    arp_lines_queue = MPQueue()
    decision_queue = MPQueue()
    producer_evt = Event()
    consumer_evt = Event()

    sniffer = Process(name='sniffer', target=sniffer_function, args=(args.file, arp_lines_queue, args.interface, producer_evt))
    worker = Process(name='worker', target=compare_oracle, args=(arp_lines_queue, conf_dico, decision_queue, producer_evt, consumer_evt))

    sniffer.start()
    worker.start()

    is_attacked = False
    while True:
        try:
            spoof_info, cpt = decision_queue.get(timeout=1)
        except Queue.Empty:
            if consumer_evt.is_set():
                break
            else:
                continue
        msg = "Alert : arpspoofing detected [attacker ip/mac : %s/%s] [victim (%s) ip/mac : %s/%s]" \
              % (spoof_info['attacker_ip'],
                 spoof_info['attacker_mac'],
                 spoof_info['victim'],
                 spoof_info['victim_ip'],
                 spoof_info['victim_mac'])
        notif(msg)
        if cpt > 5 and not is_attacked:
            attack(spoof_info['attacker_ip'])
            notif('The attacker was counter-attacked ! ')
            os.system('arptables -A INPUT -s %s -j DROP' % spoof_info['attacker_ip'])
            notif('Your are now protected from the attacker %s' % spoof_info['attacker_ip'])
            is_attacked = True

    sniffer.join()
    worker.join()

if __name__ == '__main__':
    main()
