import socket
import ssl
import threading
import os
from OpenSSL import crypto
from ssl_generator import SSLGenerator
from concurrent.futures import ThreadPoolExecutor
from statistics import Statisitics
from client import Client

class ProxyServer:
    def __init__(self, cert_ca='rootCA.crt',
                 cert_key='rootCA.key',
                 buffer_size=64000,
                 certs_folder='certificates',
                 threads_count=2 * os.cpu_count()):
        self.sever_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cert_ca = cert_ca
        self.cert_key = cert_key
        self.buffer_size = buffer_size
        self.ssl_generator = SSLGenerator(cert_ca, cert_key)
        self.threads_count = threads_count
        self.certs_folder = certs_folder
        self.statistics = Statisitics()
        self.statistics_lock = threading.RLock()

        if not os.path.exists(certs_folder):
            os.makedirs(certs_folder, exist_ok=True)

    def start(self, host='localhost', port=8080):
        self.sever_sock.bind((host, port))
        self.sever_sock.listen()
        executor = ThreadPoolExecutor(max_workers=self.threads_count - 1)

        with executor as e:
            while True:
                client_sock, addr = self.sever_sock.accept()
                e.submit(self.__handle_client, client_sock, addr)

    def __handle_client(self, client_sock, addr):
        client_ip = addr[0]
        package = self.__get_first_data(client_sock)
        host, port, is_https = self.__get_conn_info(package.decode())
        client = Client(client_sock, client_ip, host, port)

        if is_https:
            self.__handle_https(client)
        else:
            self.__handle_http(client, package)

    def __get_first_data(self, client_sock):
        client_data = self.__receive_data(client_sock)

        return client_data if client_data else None

    def __handle_http(self, client, package):
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.connect((client.remote_host, client.remote_port))
        remote_sock.sendall(package)

        try:
            while True:
                received = remote_sock.recv(self.buffer_size)
                if not received:
                    break

                client.socket.sendall(received)
        finally:
            client.socket.close()
            remote_sock.close()
            del client

    def __handle_https(self, client):
        response_message = b'HTTP/1.1 200 Connection Established\r\n\r\n'
        context = ssl.create_default_context()
        remote_sock = context.wrap_socket(socket.socket(socket.AF_INET,
                                                        socket.SOCK_STREAM),
                                          server_hostname=client.remote_host)
        remote_sock.connect((client.remote_host, client.remote_port))
        client.socket.sendall(response_message)

        cert, key = self.__create_same_cert(remote_sock)
        cert_path, key_path = self.__create_cert_key_files(client.remote_host,
                                                           cert, key)

        client.secure_sock = ssl.wrap_socket(client.socket,
                                             certfile=cert_path,
                                             keyfile=key_path,
                                             server_side=True,
                                             ssl_version=ssl.PROTOCOL_TLS,
                                             do_handshake_on_connect=False)
        try:
            self.__communicate(client, remote_sock)
        finally:
            os.remove(cert_path)
            os.remove(key_path)
            client.secure_sock.close()
            remote_sock.close()
            del client

    def __create_cert_key_files(self, file_name, cert, key):
        cert_path = '{}/{}.crt'.format(self.certs_folder, file_name)
        key_path = '{}/{}.key'.format(self.certs_folder, file_name)

        if not os.path.exists(cert_path):
            with open(cert_path, 'x') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                cert).decode())

            with open(key_path, 'x') as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,
                                               key).decode())
        return cert_path, key_path

    def __create_same_cert(self, remote_socket):
        der_cert = remote_socket.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert.encode())

        new_cert, private_key = self.ssl_generator.generate_same_cert_as(cert)

        return new_cert, private_key

    def __communicate(self, client, remote_sock):
        remote_sock.settimeout(2)
        client.secure_sock.settimeout(2)

        while True:
            data = client.secure_sock.recv(self.buffer_size)

            if not data:
                break

            if len(data) < self.buffer_size:
                remote_sock.sendall(data)
                break

            remote_sock.sendall(data)

        while True:
            server_data = remote_sock.recv(self.buffer_size)

            if not server_data:
                break

            client.secure_sock.sendall(server_data)

    def __receive_data(self, sock):
        result = b''

        while True:
            data = sock.recv(self.buffer_size)
            result = b''.join([result, data])
            if not data or len(data) < self.buffer_size:
                break

        return result if len(result) > 0 else None

    def __get_conn_info(self, package):
        package_lines = package.split('\n')
        is_https = package_lines[0].find('http') == -1
        host_line = ''

        for line in package_lines:
            if line.find('Host') >= 0:
                host_line = line
                break

        full_url = host_line.split()[1]
        port = 80
        host = full_url
        if ':' in full_url:
            host, port = full_url.split(':')

        return host, int(port), is_https

        # TODO: Tests - разбора данных,
        # http server - module для тестов сайтов
        # requests - указать какие прокси серверы использовать и принимать данные
        # и проверять эти данные

def main():
    server = ProxyServer()
    server.start('127.0.0.1', 8787)


if __name__ == '__main__':
    main()
