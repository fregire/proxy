import socket
import ssl
import threading
import os
from OpenSSL import crypto
from modules.ssl_generator import SSLGenerator
from concurrent.futures import ThreadPoolExecutor
from modules.connection import Connection
import argparse

__version__ = '1.0'
__author__ = 'Gilmutdinov Daniil'
__email__ = 'fregire@yandex.ru'


class ProxyServer:
    def __init__(self, cert_ca='rootCA.crt',
                 cert_key='rootCA.key',
                 buffer_size=64000,
                 certs_folder='certificates',
                 threads_count=2 * os.cpu_count(),
                 verbose=False,
                 show_logs=True):
        self.sever_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cert_ca = cert_ca
        self.cert_key = cert_key
        self.buffer_size = buffer_size
        self.ssl_generator = SSLGenerator(cert_ca, cert_key)
        self.threads_count = threads_count
        self.certs_folder = certs_folder
        self.recv_bytes = 0
        self.sent_bytes = 0
        self.statistics_lock = threading.RLock()
        self.show_logs = True
        self.verbose = verbose
        self.executor = ThreadPoolExecutor(max_workers=self.threads_count - 1)

        if not os.path.isfile(cert_ca):
            raise FileNotFoundError()

        if not os.path.isfile(cert_key):
            raise FileNotFoundError()

        if not os.path.exists(certs_folder):
            os.makedirs(certs_folder, exist_ok=True)

    def start(self, host='0.0.0.0', port=0):
        self.sever_sock.bind((host, port))
        self.sever_sock.listen()
        host, port = self.get_addr()
        done = False
        print('Прокси работает на ', '{}:{}'.format(host, port))

        try:
            while self.executor:
                try:
                    client_sock, addr = self.sever_sock.accept()
                    self.executor.submit(self.__handle_client,
                                         client_sock, addr)
                except KeyboardInterrupt:
                    self.show_final_stats()
                    self.show_logs = False
                    self.stop()
                    self.show_logs = True
                    break
                except socket.error as e:
                    pass
        except KeyboardInterrupt:
            self.show_final_stats()
            self.show_logs = False
            self.stop()
            self.show_logs = True
            pass

    def get_addr(self):
        curr_ip = socket.gethostbyname(socket.gethostname())
        curr_port = self.sever_sock.getsockname()[1]

        return curr_ip, curr_port

    def show_final_stats(self):
        print('Получено байт: ', self.recv_bytes)
        print('Байт отправлено: ', self.sent_bytes)

    def stop(self):
        self.sever_sock.settimeout(0)
        self.sever_sock.close()
        self.executor.shutdown()
        self.executor = None

    def __handle_client(self, client_sock, addr):
        conn_ip = addr[0]
        package = self.__receive_data(client_sock, False)
        host, port, is_https = self.get_conn_info(package)
        conn = Connection(client_sock, conn_ip, host, port)

        if is_https:
            self.__handle_https(conn)
        else:
            self.__handle_http(conn, package)

    def __handle_http(self, conn, package):
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if self.show_logs:
            log = self.get_log_info(conn, package.decode())
            if log:
                print(log)

        try:
            remote_sock.connect((conn.remote_host, conn.remote_port))
            package = self.change_to_relative_path(package.decode(),
                                                   conn, False).encode()

            remote_sock.sendall(package)
            self.update_stats(0, len(package))
            response = self.__receive_data(remote_sock, False)
            conn.socket.sendall(response)
        finally:
            conn.socket.close()
            remote_sock.close()

    @staticmethod
    def change_to_relative_path(package, conn, is_https):
        protocol = 'http'
        if is_https:
            protocol = 'https'

        abs_url_host = '{}://{}:{}'.format(protocol,
                                           conn.remote_host,
                                           conn.remote_port)
        abs_url = '{}://{}'.format(protocol,
                                   conn.remote_host)

        if package.find(abs_url_host) > -1:
            package = package.replace(abs_url_host, '')
        elif package.find(abs_url) > -1:
            package = package.replace(abs_url, '')

        return package

    def __handle_https(self, conn):
        response_message = b'HTTP/1.1 200 Connection Established\r\n\r\n'
        remote_sock = ssl.create_default_context().wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=conn.remote_host)
        remote_sock.connect((conn.remote_host, conn.remote_port))
        conn.socket.sendall(response_message)

        cert, key = self.__create_same_cert(remote_sock)
        cert_path, key_path = self.__create_cert_key_files(conn.remote_host,
                                                           cert, key)

        conn.secure_sock = ssl.wrap_socket(conn.socket,
                                           certfile=cert_path,
                                           keyfile=key_path,
                                           server_side=True,
                                           ssl_version=ssl.PROTOCOL_TLS,
                                           do_handshake_on_connect=False)
        try:
            self.__communicate(conn, remote_sock)
        finally:
            os.remove(cert_path)
            os.remove(key_path)
            conn.socket.close()
            conn.secure_sock.close()
            remote_sock.close()

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

    def __communicate(self, conn, remote_sock):
        if not conn.secure_sock:
            return None
        response = b''
        request = b''
        remote_sock.settimeout(3)
        conn.secure_sock.settimeout(3)

        request = self.__receive_data(conn.secure_sock, False)
        self.update_stats(0, len(request))
        remote_sock.sendall(request)

        if self.show_logs:
            log = self.get_log_info(conn, request.decode())
            if log:
                print(log)

        while True:
            server_data = remote_sock.recv(self.buffer_size)
            response += server_data

            if not server_data:
                break

            conn.secure_sock.sendall(server_data)
            self.update_stats(len(server_data), 0)

    def get_log_info(self, conn, package):
        if not package:
            return None
        if self.verbose:
            return package

        request_row = package.split('\n')[0]
        components = request_row.split()
        protocol = 'https:/' if conn.secure_sock else ''
        method = components[0]
        url = conn.remote_host + components[1] \
            if conn.secure_sock else components[1]
        formatted_request = '{} {}{}'.format(method, protocol, url)

        return '{} {}'.format(conn.ip, formatted_request)

    def update_stats(self, recv, sent):
        self.statistics_lock.acquire()
        self.recv_bytes += recv
        self.sent_bytes += sent
        self.statistics_lock.release()

    def __receive_data(self, sock, debug):
        result = b''
        content_length = 0

        with sock.makefile('rb') as f:
            while True:
                line = f.readline()
                result += line
                if line == b'\r\n':
                    break

                line_str = line.decode()
                con_len_pos = line_str.find('Content-Length:')
                if con_len_pos > -1:
                    content_length = int(line_str[16: len(line_str)])

            while content_length > 0:
                line = f.readline()
                result += line
                content_length -= len(line) + 2

        return result if len(result) > 0 else None

    @staticmethod
    def get_conn_info(package):
        package = package.decode()
        package_lines = package.split('\n')
        is_https = package_lines[0].find('http') == -1
        host_line = next((line for line in package_lines
                          if line.find('Host') >= 0), None)
        full_url = host_line.split()[1]
        port = 80
        host = full_url
        if ':' in full_url:
            host, port = full_url.split(':')

        return host, int(port), is_https


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verbose',
                        help='Показывать пакеты целиком в логах',
                        action='store_true')
    parser.add_argument('--no-log',
                        help='Не показывать логи',
                        action='store_true')
    parser.add_argument('-p',
                        '--port',
                        type=int,
                        help='Порт для прокси')

    return parser.parse_args()


def main():
    args = parse_args()
    verbose = args.verbose
    port = args.port if args.port else 3228
    log = not args.no_log

    try:
        server = ProxyServer(verbose=verbose, show_logs=log)
        server.start(port=port)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
