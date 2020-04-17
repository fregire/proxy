import socket


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 8888))
    sock.send(b'Hello, world! Client2')
    sock.close()

if __name__ == '__main__':
    main()
