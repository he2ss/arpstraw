import unittest
import Queue
from sniffer import Sniffer
from oracles import WorkerManager, rq

f = 'frames/trame.cap'
blacklist = [line.strip() for line in open('lists/mysql_list.txt', 'r')]
q = Queue.Queue

sniffer = Sniffer('mysql', blacklist, q, 'frames/trame-test1.cap', f)
worker = WorkerManager(blacklist, q, f)


class Tests(unittest.TestCase):

    def test_rename_port(self):
        self.assertEqual(sniffer.__rename_port, {'3306'})