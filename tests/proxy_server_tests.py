import unittest
from proxy_server import ProxyServer
import os

class ProxyServerTests(unittest.TestCase):
    def test_init_options(self):
        server = ProxyServer(cert_ca='../rootCA.crt', cert_key='../rootCA.key',
                             certs_folder='../certificates')
        certs_path_exist = False

        if os.path.exists(server.certs_folder):
            certs_path_exist = True

        self.assertEqual(certs_path_exist, True)

    def test_http_package_parsing(self):
        with open('packages/http_package') as f:
            package = f.read().encode()
            host, port, is_https = ProxyServer.get_conn_info(package)

            self.assertEqual('scratchpads.eu', host)
            self.assertEqual(80, port)
            self.assertEqual(False, is_https)

    def test_https_package_parsing(self):
        with open('packages/https_package') as f:
            package = f.read().encode()
            host, port, is_https = ProxyServer.get_conn_info(package)

            self.assertEqual('anytask.org', host)
            self.assertEqual(443, port)
            self.assertEqual(True, is_https)
