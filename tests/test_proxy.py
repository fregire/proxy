import unittest
import os
import sys
import requests
import socket
import threading
import time
from http.server import HTTPServer, CGIHTTPRequestHandler, ThreadingHTTPServer
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from proxy_server import ProxyServer

PACKAGES_DIR = 'tests/packages/'
ROOT_CRT = 'rootCA.crt'
ROOT_KEY = 'rootCA.key'
CERTIFICATES_FOLDER = 'certificates'
WEB_SERVER_ADDRESS = ('localhost', 8081)

class ProxyServerTests(unittest.TestCase):
    def test_init_options(self):
        server = ProxyServer(cert_ca=ROOT_CRT, cert_key=ROOT_KEY,
                             certs_folder=CERTIFICATES_FOLDER)
        certs_path_exist = False

        if os.path.exists(server.certs_folder):
            certs_path_exist = True

        self.assertEqual(certs_path_exist, True)

    def test_http_package_parsing(self):
        with open(PACKAGES_DIR + 'http_package') as f:
            package = f.read().encode()
            host, port, is_https = ProxyServer.get_conn_info(package)

            self.assertEqual('scratchpads.eu', host)
            self.assertEqual(80, port)
            self.assertEqual(False, is_https)

    def test_https_package_parsing(self):
        with open(PACKAGES_DIR + 'https_package') as f:
            package = f.read().encode()
            host, port, is_https = ProxyServer.get_conn_info(package)

            self.assertEqual('anytask.org', host)
            self.assertEqual(443, port)
            self.assertEqual(True, is_https)

    def test_starting_stopping_server(self):
        proxy = ProxyServer()
        expected_host = socket.gethostbyname(socket.gethostname())
        expected_port = 1111

        host, port = proxy.start(host='0.0.0.0', port=expected_port)
        proxy.stop()

        self.assertEqual(host, expected_host)
        self.assertEqual(port, expected_port)
        self.assertEqual(proxy.sever_sock.fileno(), -1)
        self.assertIsNone(proxy.executor)

    def test_handling_clients_http(self):
        url = 'http://{}:{}'.format(WEB_SERVER_ADDRESS[0],
                                     WEB_SERVER_ADDRESS[1])
        print('Starting')
        server = HTTPServer(WEB_SERVER_ADDRESS, CGIHTTPRequestHandler)
        proxy = ProxyServer()
        host, port = proxy.start()
        proxy_url = 'http://{}:{}'.format(host, port)
        th = threading.Thread(target=server.serve_forever)
        th.start()

        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }

        r = requests.get(url, proxies=proxies)
        self.assertEqual(r.status_code, 404)
        proxy.stop()
        server.shutdown()
        th.join()



