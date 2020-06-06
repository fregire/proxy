import socket


class Connection:
    def __init__(self, sock, ip, remote_host, remote_port):
        self.socket = sock
        self.ip = ip
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.secure_sock = None
