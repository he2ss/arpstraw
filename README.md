# ARPStraw

arpstraw is an open source [![MITM](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)] detection tool that notify user when it detect an ArpSpoof attack. It rests on a config file ```arpstraw.cfg``` where you can specify each host you know in your network.

Installation
----

This program required root permission to work.
For the installation you need ```pip``` to install the requirements.

```bash
git clone https://github.com/he2ss/arpstraw.git

pip install -r requirements.txt
```

Before the usage, you must copy the ```template.cfg``` file and rename it to ```arpspoof.cfg``` and specify the hosts you know on you network. For example your router ip/mac addresses and other hosts you want.

Usage
----

To get the tool help :

    sudo python main.py -h

To launch detection on a interface :

    sudo python main.py -i eth0

To launch detction on a pcap : 
    
    sudo python main.py -f myfile.pcap