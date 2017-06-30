import argparse
import logging
import Queue
import collections
import ConfigParser
import os
from multiprocessing import Process, Queue as MPQueue, Event
import netifaces
import re

from sniffer import arp_parser, sql_parser
from oracle import arp_oracle, sql_oracle

from pyshark.packet import layer

FIELDS = ['host', 'method', 'uri', 'user_agent', 'ip_src', 'ip_dst']


class LayerFieldsContainer(layer.LayerFieldsContainer):
    def __new__(cls, main_field, *args, **kwargs):
        if hasattr(main_field, 'get_default_value'):
            obj = str.__new__(cls, main_field.get_default_value(), *args, **kwargs)
        else:
            obj = str.__new__(cls, main_field, *args, **kwargs)
        obj.fields = [main_field]
        return obj
layer.LayerFieldsContainer = LayerFieldsContainer


#if os.getuid() != 0:
#    exit("Error: root permission is required to run this program !")

FORMAT = "%(asctime)-15s %(message)s"
logging.basicConfig(filename='arpstraw.log', filemode='a', level=logging.INFO, format=FORMAT)


parser = argparse.ArgumentParser(description='Angry ')
parser.add_argument('-f', '--file', default=None, type=argparse.FileType('r'), help="Specify file to analyse")
parser.add_argument('-i', '--interface', default=None, type=str, help="Specify interface eth0|lo|eth1 ...")
parser.add_argument('-mod', '--module', default='arp', type=str, help="Specify module ( arp | sql )", required=True)
args = parser.parse_args()

config = ConfigParser.ConfigParser()
if args.module is "arp":
    if os.path.exists('arpstraw.cfg'):
        config.read('arpstraw.cfg')
        conf_dico = collections.defaultdict(lambda: collections.defaultdict())
        for section in config.sections():
            for item in config.options(section):
                conf_dico[section][item] = config.get(section, item)
    else:
        exit("Error : can't open arpstraw.cfg file !")
        logging.info("Error : can't open arpstraw.cfg file !")


def main():

    if args.file is None:
        if args.interface is None:
            parser.error('required parameters : -i/--interface INTERFACE')
        else:
            interfaces = netifaces.interfaces()
            if args.interface not in interfaces:
                print('ERROR: please specify a valid interface : \n%s' % ' | '.join(interfaces))
                return

    lines_queue = MPQueue()
    decision_queue = MPQueue()
    producer_evt = Event()
    consumer_evt = Event()

    if args.module == "arp":
        sniffer = Process(name='sniffer', target=arp_parser, args=(args.file, lines_queue, args.interface, producer_evt))
        worker = Process(name='worker', target=arp_oracle, args=(lines_queue, conf_dico, decision_queue, producer_evt, consumer_evt))
    if args.module == "sql":
        re_list = open('lists/re_sql.txt', 'r')
        re_dict = {}
        compiled_list = []
        nb_line = 0
        for regex in re_list.readlines():
            nb_line += 1
            if regex.startswith("#"):
                continue
            if regex.startswith("!"):
                fields = regex[1:].split(":")
                fields[0] = fields[0].lower()
                if fields[0] in FIELDS:
                    re_dict[fields[0]] = re.compile(fields[1].strip(), re.IGNORECASE)
                else:
                    parser.error("Field ( %s ) doesn't exist, line %s" % (fields[0], nb_line))
            try:
                compiled_list.append(re_dict)
                re_dict = {}
            except Exception as e:
                print(e)
                exit(0)
        sniffer = Process(name='sniffer', target=sql_parser, args=(args.file, lines_queue, args.interface, producer_evt))
        worker = Process(name='worker', target=sql_oracle, args=(lines_queue, decision_queue, compiled_list, producer_evt, consumer_evt))

    sniffer.start()
    worker.start()

    while True:
        try:
            dict_info = decision_queue.get(timeout=1)
        except Queue.Empty:
            if consumer_evt.is_set():
                break
            else:
                continue
        if args.module == "arp":
            msg = "[alert] : arpspoofing detected [attacker ip/mac : %s/%s] [victim (%s) ip/mac : %s/%s]" \
                  % (dict_info['attacker_ip'],
                     dict_info['attacker_mac'],
                     dict_info['victim'],
                     dict_info['victim_ip'],
                     dict_info['victim_mac'])
        if args.module == "sql":
            msg = "[alert] : sql injection detected [ip_src : %s] [ip_dst : %s] [%s : %s]" \
                  % (dict_info['ip_src'],
                     dict_info['ip_dst'],
                     dict_info['field'],
                     dict_info[dict_info['field']])
        logging.warning(msg)
        print(msg)

    sniffer.join()
    worker.join()

if __name__ == '__main__':
    main()
