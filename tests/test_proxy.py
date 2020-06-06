import unittest
import os
import sys
import requests
import socket
import threading
import time
import ssl

from http.server import HTTPServer, CGIHTTPRequestHandler
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from proxy_server import ProxyServer
from modules import connection


ROOT_CRT = 'rootCA.crt'
ROOT_KEY = 'rootCA.key'
CERTIFICATES_FOLDER = 'certificates'
WEB_SERVER_ADDRESS = ('localhost', 8081)
HTTP_PACKAGE = 'tests/packages/http_package'
HTTPS_PACKAGE = 'tests/packages/https_package'
CLIENT_IP = '156.90.34.123'
BUFFER_SIZE = 1024
SUCCESS_MESSAGE = b'HTTP/1.1 200 Connection Established\r\n\r\n'


class ProxyServerTests(unittest.TestCase):
    def test_init_options(self):
        server = ProxyServer(cert_ca=ROOT_CRT, cert_key=ROOT_KEY,
                             certs_folder=CERTIFICATES_FOLDER)
        certs_path_exist = False

        if os.path.exists(server.certs_folder):
            certs_path_exist = True

        self.assertEqual(certs_path_exist, True)

    def test_http_package_parsing(self):
        with open(HTTP_PACKAGE) as f:
            package = f.read().encode()
            host, port, is_https = ProxyServer.get_conn_info(package)

            self.assertEqual('scratchpads.eu', host)
            self.assertEqual(80, port)
            self.assertEqual(False, is_https)

    def test_https_package_parsing(self):
        with open(HTTPS_PACKAGE) as f:
            package = f.read().encode()
            host, port, is_https = ProxyServer.get_conn_info(package)

            self.assertEqual('anytask.org', host)
            self.assertEqual(443, port)
            self.assertEqual(True, is_https)

    def test_starting_stopping_server(self):
        proxy = ProxyServer()
        expected_host = socket.gethostbyname(socket.gethostname())
        expected_port = 1111

        th = threading.Thread(target=proxy.start,
                              kwargs={
                                  'host': '0.0.0.0',
                                  'port': expected_port})
        th.start()
        time.sleep(0.1)
        host, port = proxy.get_addr()
        proxy.stop()

        self.assertEqual(host, expected_host)
        self.assertEqual(port, expected_port)
        self.assertEqual(proxy.sever_sock.fileno(), -1)
        self.assertIsNone(proxy.executor)

    def test_handling_clients(self):
        url = 'http://{}:{}'.format(WEB_SERVER_ADDRESS[0],
                                    WEB_SERVER_ADDRESS[1])
        print('Starting')
        server = HTTPServer(WEB_SERVER_ADDRESS, CGIHTTPRequestHandler)
        proxy = ProxyServer()
        proxy_th = threading.Thread(target=proxy.start)
        http_th = threading.Thread(target=server.serve_forever)
        proxy_th.start()
        http_th.start()

        proxy_url = 'http://{}:{}'.format(*proxy.get_addr())
        proxies = {
            'http': proxy_url
        }

        r = requests.get(url, proxies=proxies)
        self.assertEqual(r.status_code, 200)
        proxy.stop()
        server.shutdown()
        http_th.join()
        proxy_th.join()

    def test_handling_https(self):
        context = ssl.create_default_context()
        proxy = ProxyServer()
        th = threading.Thread(target=proxy.start)
        th.start()

        host, port = proxy.get_addr()
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        serv.connect((host, port))

        with open(HTTPS_PACKAGE) as f:
            serv.sendall(f.read().encode())

        response = b''
        while True:
            data = serv.recv(BUFFER_SIZE)
            if not data:
                break
            response += data

        self.assertEqual(SUCCESS_MESSAGE, response)
        serv.close()
        proxy.stop()
        th.join()

    def test_log_info(self):
        proxy = ProxyServer()
        conn = connection.Connection(None, CLIENT_IP, 'scratchpads.eu', 80)

        with open(HTTP_PACKAGE) as f:
            package = f.read()

        result = proxy.get_log_info(conn, package)
        self.assertEqual(result,
                         CLIENT_IP + ' POST '
                         'http://scratchpads.eu/modules/'
                         'statistics/statistics.php')
