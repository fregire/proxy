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
HTTP_PACKAGE = b'POST ' \
               b'http://scratchpads.eu/modules/statistics/statistics.php ' \
               b'HTTP/1.1\r\n' \
               b'Host: scratchpads.eu\r\n' \
               b'Proxy-Connection: keep-alive\r\nContent-Length: 6\r\n' \
               b'Accept: */*\r\n' \
               b'X-Requested-With: XMLHttpRequest\r\n' \
               b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' \
               b'AppleWebKit/537.36 (KHTML, like Gecko) ' \
               b'Chrome/83.0.4103.61 Safari/537.36\r\n' \
               b'Content-Type: application/x-www-form-urlencoded\r\n' \
               b'Origin: http://scratchpads.eu\r\n' \
               b'Referer: http://scratchpads.eu/explore/sites-list\r\n' \
               b'Accept-Encoding: gzip, deflate\r\n' \
               b'Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\n' \
               b'Cookie: _ga=GA1.2.694315185.1585324292; _' \
               b'gid=GA1.2.211823458.1590225723; has_js=1; _gat=1\r\n' \
               b'nid=13\r\n\r\n'
HTTPS_PACKAGE = b'CONNECT anytask.org:443 HTTP/1.1\r\n' \
                b'Host: anytask.org:443\r\n' \
                b'Proxy-Connection: keep-alive\r\n' \
                b'User-Agent: Mozilla/5.0 ' \
                b'(Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' \
                b'(KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36\r\n' \
                b'\r\n'
SUCCESS_MESSAGE = b'HTTP/1.1 200 Connection Established\r\n\r\n'
CLIENT_IP = '156.90.34.123'
BUFFER_SIZE = 1024


class ProxyServerTests(unittest.TestCase):
    def test_init_options(self):
        server = ProxyServer(cert_ca=ROOT_CRT, cert_key=ROOT_KEY,
                             certs_folder=CERTIFICATES_FOLDER)
        certs_path_exist = False

        if os.path.exists(server.certs_folder):
            certs_path_exist = True

        self.assertEqual(certs_path_exist, True)

    def test_http_package_parsing(self):
        host, port, is_https = ProxyServer.get_conn_info(HTTP_PACKAGE)

        self.assertEqual('scratchpads.eu', host)
        self.assertEqual(80, port)
        self.assertEqual(False, is_https)

    def test_https_package_parsing(self):
        host, port, is_https = ProxyServer.get_conn_info(HTTPS_PACKAGE)

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
        self.assertEqual(proxy.executor, None)

    def test_handling_https(self):
        context = ssl.create_default_context()
        proxy = ProxyServer()
        th = threading.Thread(target=proxy.start)
        th.start()

        host, port = proxy.get_addr()
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        serv.connect((host, port))
        serv.sendall(HTTPS_PACKAGE)

        response = b''
        while True:
            data = serv.recv(BUFFER_SIZE)
            if not data:
                break
            response += data
        self.assertEqual(SUCCESS_MESSAGE, response)
        proxy.stop()
        th.join()

    def test_log_info(self):
        proxy = ProxyServer()
        conn = connection.Connection(None, CLIENT_IP, 'scratchpads.eu', 80)

        result = proxy.get_log_info(conn, HTTP_PACKAGE.decode())
        self.assertEqual(result,
                         CLIENT_IP + ' POST '
                         'http://scratchpads.eu/modules/'
                         'statistics/statistics.php')