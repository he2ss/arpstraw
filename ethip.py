# The MIT License (MIT)
# 
# Copyright (c) 2014 David Mulder
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os, pickle
from subprocess import Popen, PIPE
from scapy.all import srp, Ether, ARP, conf
from multiprocessing import Process, Pool

class Cache:
    def __init__(self):
        self._cache = None
        settings_dir = os.path.join(os.path.expanduser('~'), '.config/eth_ip/')
        if not os.path.exists(settings_dir):
            os.makedirs(settings_dir)
        self.settings_path = os.path.join(settings_dir, 'eth_ip_settings')

    def __enter__(self):
        if not os.path.exists(self.settings_path):
            self._cache = {}
        else:
            self._cache = pickle.load(open(self.settings_path, 'r'))
        return self

    def __getitem__(self, key):
        return self._cache[key.lower()]

    def __setitem__(self, key, value):
        self._cache[key.lower()] = value.lower()

    def pop(self, key):
        self._cache.pop(key.lower())

    def __delitem__(self, key):
        self._cache.pop(key.lower())

    def __contains__(self, key):
        return key.lower() in self._cache.keys()

    def __exit__(self, type, value, traceback):
        pickle.dump(self._cache, open(self.settings_path, 'w'))

class Subnet:
    def __init__(self, subnet):
        self.subnet = subnet.split('.')
        if len(self.subnet) != 4:
            raise Exception('Invalid subnet')

    def children(self):
        addrs = []
        if self.subnet[0] == '255':
            for sn in ['%s.255.255.255' % i for i in range(1, 255)]:
                addrs.extend(Subnet(sn).children())
        elif self.subnet[1] == '255':
            for sn in ['%s.%s.255.255' % (self.subnet[0], i) for i in range(1, 255)]:
                addrs.extend(Subnet(sn).children())
        elif self.subnet[2] == '255':
            for sn in ['%s.%s.%s.255' % (self.subnet[0], self.subnet[1], i) for i in range(1, 255)]:
                addrs.extend(Subnet(sn).children())
        elif self.subnet[3] == '255':
            addrs.extend(['%s.%s.%s.%s' % (self.subnet[0], self.subnet[1], self.subnet[2], i) for i in range(1, 255)])
        else:
            addrs.append('.'.join(self.subnet))
        return addrs

def _known_addrs(rev=False):
    """Ask arp for ip to mac address mappings"""
    if not rev:
        return dict((line.strip().split()[2].lower(), line.strip().split()[0]) for line in Popen(['grep', 'ether'], stdin=Popen(['arp', '-n'], stdout=PIPE).stdout, stdout=PIPE).communicate()[0].strip().split('\n'))
        #return {line.strip().split()[2].lower():line.strip().split()[0] for line in Popen(['grep', 'ether'], stdin=Popen(['arp', '-n'], stdout=PIPE).stdout, stdout=PIPE).communicate()[0].strip().split('\n')}
    else:
        return dict((line.strip().split()[0], line.strip().split()[2].lower()) for line in Popen(['grep', 'ether'], stdin=Popen(['arp', '-n'], stdout=PIPE).stdout, stdout=PIPE).communicate()[0].strip().split('\n'))
        #return {line.strip().split()[0]:line.strip().split()[2].lower() for line in Popen(['grep', 'ether'], stdin=Popen(['arp', '-n'], stdout=PIPE).stdout, stdout=PIPE).communicate()[0].strip().split('\n')}

def _arp_request(ip_addr):
    """Send an ARP request for the IP address"""
    answer, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_addr), verbose=0, timeout=.5)
    if answer:
        return (answer[0][1].src, answer[0][0].pdst)

def getip(mac, subnet):
    """Find the ip address from a given mac address and search subnet (example: 10.5.32.255 or 10.5.255.255)."""
    address = None
    known = _known_addrs()
    if mac.lower() in known.keys():
        address = known[mac.lower()]
    if not address and os.geteuid() == 0:
        with Cache() as cache:
            if mac in cache:
                verify = _arp_request(cache[mac])
                if verify and verify[0].lower() == mac.lower():
                    address = verify[1]
                elif verify:
                    cache[verify[0]] = verify[1]
                else:
                    cache.pop(mac)
            if not address:
                addrs = [ad for ad in Subnet(subnet).children() if not ad in known.values()]
                pool = Pool(50)
                mac_addrs = [ad for ad in pool.map(_arp_request, addrs) if ad]
                for mac_addr in mac_addrs:
                    cache[mac_addr[0]] = mac_addr[1]
                if mac in cache:
                    address = cache[mac]
    return address

def getmac(ip):
    """Find the mac address from a given ip address."""
    known = _known_addrs(True)
    if ip in known.keys():
        return known[ip]
    elif os.geteuid() == 0:
        req = _arp_request(ip)
        if req:
            return req[0]

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print '\n\t%s mac_address subnet\n' % sys.argv[0]
        exit(0)
    mac = sys.argv[1]
    subnet = sys.argv[2]
    ip = getip(mac, subnet)
    print 'Requested ip address:', ip
    print 'Requested mac address:', getmac(ip)
