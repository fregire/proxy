import socket
import threading
import os
from concurrent.futures import ThreadPoolExecutor
import argparse
from modules.connection import Connection
from modules.statistics import Statistics
import select


__version__ = '1.0'
__author__ = 'Gilmutdinov Daniil'
__email__ = 'fregire@yandex.ru'
RESPONSE_MESSAGE = b'HTTP/1.1 200 Connection Established\r\n\r\n'
TRANSFER_ENCODING_HEADER = b'Transfer-Encoding: chunked\r\n'
CONTENT_LEN_HEADER = b'Content-Length:'


class ProxyServer:
    def __init__(self, buffer_size=65535,
                 threads_count=os.cpu_count() * 2,
                 verbose=False,
                 show_logs=True):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.buffer_size = buffer_size
        self.threads_count = threads_count
        self.stats = Statistics()
        self.stats_lock = threading.RLock()
        self.show_logs = show_logs
        self.verbose = verbose
        self.executor = ThreadPoolExecutor(max_workers=self.threads_count - 1)

    def start(self, host='0.0.0.0', port=0):
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.server_sock.bind((host, port))
        self.server_sock.listen()
        host, port = self.get_server_addr()

        print('Прокси работает на ', '{}:{}'.format(host, port))

        while self.executor:
            client_sock, addr = self.server_sock.accept()
            self.executor.submit(self.__handle_client,
                                 client_sock, addr)

    def stop(self):
        self.server_sock.settimeout(0)
        self.server_sock.close()
        self.executor.shutdown()
        self.executor = None

    def show_final_stats(self):
        print('Получено байт: ', self.stats.received_bytes)
        print('Байт отправлено: ', self.stats.sent_bytes)

    def get_server_addr(self):
        curr_ip = socket.gethostbyname(socket.gethostname())
        curr_port = self.server_sock.getsockname()[1]

        return curr_ip, curr_port

    def __handle_client(self, client_sock, addr):
        conn_ip = addr[0]
        package = self.__receive_data(client_sock, 1.5)
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
        except:
            pass

    def __communicate(self, conn, remote_sock):
        #conn.socket.setblocking(0)
        #remote_sock.setblocking(0)
        with conn.socket:
            with remote_sock:
                while True:
                    readers, _, _ = select.select([conn.socket, remote_sock], [], [])
                    has_data = False

                    for i, reader in enumerate(readers):
                        data = reader.recv(self.buffer_size)
                        if data:
                            has_data = True

                            if reader is conn.socket:
                                remote_sock.sendall(data)
                            else:
                                conn.socket.sendall(data)

                    if not has_data:
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
        with self.stats_lock:
            self.stats.update(recv, sent)

    def __receive_data(self, sock, timeout=None):
        result = b''

        if timeout:
            sock.settimeout(timeout)

        while True:
            try:
                data = sock.recv(self.buffer_size)
            except socket.error:
                return result

            if not data:
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
    port = args.port if args.port else 0
    show_logs = not args.no_log

    try:
        server = ProxyServer(verbose=verbose, show_logs=show_logs)
        server.start(port=port)
    except KeyboardInterrupt:
        server.stop()
        server.show_final_stats()
        pass


if __name__ == '__main__':
    main()
