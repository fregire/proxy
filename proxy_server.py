import socket
import ssl
import threading
from OpenSSL import crypto

class ProxyServer:
    def __init__(self):
        #SSL options
        self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                               open('rootCA.crt').read())
        self.ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                              open('rootCA.key').read())
        self.serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host='localhost', port=8080):
        self.serverSock.bind((host, port))
        self.serverSock.listen(5)

        while True:
            try:
                client_sock, addr = self.serverSock.accept()
                print('New connection', addr)
            except KeyboardInterrupt:
                break
            else:
                thread = threading.Thread(target=self.__handle_client,
                                          args=(client_sock,),
                                          daemon=True)
                thread.start()
                print(threading.active_count())

    def __handle_client(self, client_sock):
        client_data = self.__recv_data(client_sock, 1024)
        if not client_data:
            return None

        package = client_data.decode()
        host, port = self.__get_host_and_port(package)

        # TODO: DETERMINE SAFE PORT
        if port == 80:
            self.__handle_http(client_sock, client_data, host, port)

        if port == 443:
            self.__handle_https(client_sock, client_data, host, port)

    def __handle_http(self, client_sock, data, host, port):
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.connect((host, port))
        remote_sock.sendall(data)

        while True:
            received = remote_sock.recv(512)

            if not received:
                break

            client_sock.sendall(received)

        client_sock.close()

    def __handle_https(self, client_sock, data, host, port):
        server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock = ssl.wrap_socket(server_conn,
                                      server_side=False,
                                      certfile='server.crt',
                                      keyfile='server.key',
                                      ssl_version=ssl.PROTOCOL_TLS)

        #self.__get_cert_info((host, port))
        #
        remote_sock.connect((host, port))
        client_sock.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

        #Getting SSL certificate from remote server
        der_cert = remote_sock.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        print(pem_cert)

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert.encode())

        self.generate_cert(cert)


        # [(b'C', b'US'), (b'ST', b'California'), (b'L', b'San Francisco'),
        # (b'O', b'GitHub, Inc.'), (b'CN', b'*.github.com')]
        #DNS:*.github.com, DNS:github.com
        #print(cert.get_subject().get_components())

        #
        sclient = ssl.wrap_socket(client_sock,
                                  certfile='server.crt',
                                  keyfile='server.key',
                                  server_side=True,
                                  ssl_version=ssl.PROTOCOL_TLS,
                                  do_handshake_on_connect=False)

        client_data = sclient.recv(1024)
        print(client_data)
        remote_sock.sendall(client_data)

        while True:
            server_data = remote_sock.recv(1024)

            if not server_data:
                client_data = sclient.recv(1024)

                if not client_data:
                    break


            sclient.sendall(server_data)
            remote_sock.sendall(client_data)


    def __recv_data(self, socket, data_len):
        result = b''

        while True:
            data = socket.recv(data_len)
            result += data

            if not data or len(data) < data_len:
                break

        return result if len(result) > 0 else None

    def __get_host_and_port(self, package):
        package_lines = package.split('\n')
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

        return host, int(port)

        # TODO: Tests - разбора данных,
        # http server - module для тестов сайтов
        # requests - указать какие прокси серверы использовать и принимать данные
        # и проверять эти данные
    def generate_cert(self, remote_cert):
        #Public Key
        pub_key = crypto.PKey()
        pub_key.generate_key(crypto.TYPE_RSA, 2048)

        #Extensions (SAN)
        extensions = []

        for i in range(remote_cert.get_extension_count()):
            ext = remote_cert.get_extension(i)
            #Find SAN in certificate
            if ext.get_short_name().decode() == 'subjectAltName':
                extensions.append(crypto.X509Extension(b'subjectAltName',
                                                       False,
                                                       str(ext).encode()))

        #Generate request
        cert = crypto.X509()
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_subject(remote_cert.get_subject())
        cert.set_pubkey(pub_key)
        cert.add_extensions(extensions)
        cert.sign(self.ca_key, 'sha256')

        return cert, pub_key


def main():
    server = ProxyServer()
    #server.start('127.0.0.1', 8787)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                   open('server.crt').read())

    res_cert, key = ProxyServer.generate_cert(server, cert)
    print(crypto.dump_certificate(crypto.FILETYPE_PEM, res_cert))

if __name__ == '__main__':
    main()
