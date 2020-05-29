import unittest
from modules.statistics import Statistics
from modules.connection import Connection
import socket


class StatisticsTests(unittest.TestCase):
    def test_update(self):
        stat = Statistics()
        test_num = 100
        conn_first = Connection(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                          '127.0.0.1', 'anytask.org', 443)
        conn_second = Connection(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                          '187.0.1.128', 'testing.ru', 80)

        stat.update(conn_first, test_num, 0)

        self.assertDictEqual({'127.0.0.1': {'anytask.org': (test_num, 0)}},
                             stat.clients)

        stat.update(conn_first, test_num, test_num)

        self.assertDictEqual({'127.0.0.1': {'anytask.org': (test_num * 2, test_num)}},
                             stat.clients)

        stat.update(conn_second, 0, test_num)

        self.assertDictEqual({'127.0.0.1': {'anytask.org': (test_num * 2, test_num)},
                              '187.0.1.128': {'testing.ru': (0, test_num)}},
                             stat.clients)
        conn_first.socket.close()
        conn_second.socket.close()
