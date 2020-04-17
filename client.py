import socket


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 8888))
    sock.send(b'Hello, world! Clien1')
    sock.close()

if __name__ == '__main__':
    main()
