import socket
import threading
import os
from concurrent.futures import ThreadPoolExecutor
from connection import Connection
import argparse
from statistics import Statistics

__version__ = '1.0'
__author__ = 'Gilmutdinov Daniil'
__email__ = 'fregire@yandex.ru'
RESPONSE_MESSAGE = b'HTTP/1.1 200 Connection Established\r\n\r\n'
TRANSFER_ENCODING_HEADER = b'Transfer-Encoding: chunked\r\n'
CONTENT_LEN_HEADER = b'Content-Length:'


class ProxyServer:
    def __init__(self, buffer_size=64000,
                 threads_count=2 * os.cpu_count(),
                 verbose=False,
                 show_logs=True):
        self.sever_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.buffer_size = buffer_size
        self.threads_count = threads_count
        self.stats = Statistics()
        self.stats_lock = threading.RLock()
        self.show_logs = show_logs
        self.verbose = verbose
        self.executor = ThreadPoolExecutor(max_workers=self.threads_count - 1)

    def start(self, host='0.0.0.0', port=0):
        self.sever_sock.bind((host, port))
        self.sever_sock.listen()
        host, port = self.get_server_addr()

        print('Прокси работает на ', '{}:{}'.format(host, port))

        try:
            while self.executor:
                try:
                    client_sock, addr = self.sever_sock.accept()
                    self.executor.submit(self.__handle_client,
                                         client_sock, addr)
                except KeyboardInterrupt:
                    print('Stopped inner')
                    self.stop()
                    self.show_final_stats()
                    self.sever_sock.close()
                    pass
        except KeyboardInterrupt:
            print('Stopped outer')
            self.stop()
            self.show_final_stats()
            self.sever_sock.close()
            pass

    def stop(self):
        self.sever_sock.settimeout(0)
        self.sever_sock.close()
        self.executor.shutdown()
        self.executor = None

    def show_final_stats(self):
        print('Получено байт: ', self.stats.received_bytes)
        print('Байт отправлено: ', self.stats.sent_bytes)

    def get_server_addr(self):
        curr_ip = socket.gethostbyname(socket.gethostname())
        curr_port = self.sever_sock.getsockname()[1]

        return curr_ip, curr_port

    def __handle_client(self, client_sock, addr):
        conn_ip = addr[0]
        package = self.__receive_data(client_sock)
        host, port, is_https = self.get_conn_info(package)
        conn = Connection(client_sock, conn_ip, host, port)

        if not package:
            return None

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
            remote_sock.sendall(package)
            self.update_stats(0, len(package))
            self.transfer_http_data(remote_sock.makefile('rb'), conn.socket)
        finally:
            conn.socket.close()
            remote_sock.close()

    def __handle_https(self, conn):
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.connect((conn.remote_host, conn.remote_port))
        conn.socket.sendall(RESPONSE_MESSAGE)

        try:
            self.__communicate(conn, remote_sock)
        finally:
            conn.socket.close()
            conn.secure_sock.close()
            remote_sock.close()

    def __communicate(self, conn, remote_sock):
        while True:
            request = self.__receive_data(conn.socket, timeout=2)
            if request:
                remote_sock.sendall(request)
                self.update_stats(0, len(request))

            response = self.__receive_data(remote_sock, timeout=2)
            if response:
                conn.socket.sendall(response)
                self.update_stats(len(response), 0)

            if not response and not request:
                break

    def get_header_info(self, src):
        content_len = 0
        resp_header = b''
        is_chunked = False

        while True:
            line = src.readline()
            resp_header += line
            if line == TRANSFER_ENCODING_HEADER:
                is_chunked = True
            if line[:15] == CONTENT_LEN_HEADER:
                content_len = int(line[15:-2].decode())
            if line == b'\r\n' or not line:
                break

        return resp_header, is_chunked, content_len

    def transfer_http_data(self, remote_sock_file, client_sock):
        response, is_chunked, content_len = self.get_header_info(remote_sock_file)

        if is_chunked:
            client_sock.sendall(response)
            self.update_stats(len(response), 0)
            response = b''

            while True:
                line = remote_sock_file.readline()
                response += line
                if line == b'0\r\n':
                    response += b'\r\n'
                    break
                if not line:
                    break

                num = int(line[:-2].decode(), 16)
                chunk = remote_sock_file.read(num + 2)
                response += chunk
                client_sock.sendall(response)
                self.update_stats(len(response), 0)

                response = b''

        if content_len != 0:
            body = remote_sock_file.read(content_len)
            response += body

        client_sock.sendall(response)
        self.update_stats(len(response), 0)

    def get_log_info(self, conn, package):
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
        self.stats_lock.acquire()
        self.stats.update(recv, sent)
        self.stats_lock.release()

    def __receive_data(self, sock, timeout=None):
        result = b''

        if timeout:
            sock.settimeout(timeout)

        while True:
            try:
                data = sock.recv(self.buffer_size)
            except socket.error:
                return result

            if not data or len(data) < self.buffer_size:
                result += data
                break

            result += data

        return result

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
    show_logs = not args.no_log

    try:
        server = ProxyServer(verbose=verbose, show_logs=True)
        server.start(port=port)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
