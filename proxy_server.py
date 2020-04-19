import socket
import ssl
import threading
from OpenSSL import crypto
import os

class SSLGenerator:
    def __init__(self, path_ca_cert, path_ca_key):
        self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                               open(path_ca_cert).read())

        self.ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                             open(path_ca_key).read())

    def generate_same_cert_as(self, remote_cert):
        # Public Key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Extensions (SAN)
        extensions = []

        for i in range(remote_cert.get_extension_count()):
            ext = remote_cert.get_extension(i)
            # Find SAN in certificate
            if ext.get_short_name() == b'subjectAltName':
                extensions.append(crypto.X509Extension(b'subjectAltName',
                                                       False,
                                                       str(ext).encode()))



        # Generate request
        cert = crypto.X509()

        for component in remote_cert.get_subject().get_components():
            if component[0] == b'CN':
                cert.get_subject().CN = component[1]
            if component[0] == b'L':
                cert.get_subject().L = component[1]
            if component[0] == b'O':
                cert.get_subject().O = component[1]
            if component[0] == b'ST':
                cert.get_subject().ST = component[1]
            if component[0] == b'OU':
                cert.get_subject().OU = component[1]
            if component[0] == b'C':
                cert.get_subject().C = component[1]

        extensions.append(
            crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'))

        extensions.append(
            crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash',
                                 subject=cert))
        extensions.append(crypto.X509Extension(b'authorityKeyIdentifier', False,
                                               b'keyid:always,issuer:always',
                                               subject=self.ca_cert,
                                               issuer=self.ca_cert))

        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_serial_number(1000)
        cert.set_pubkey(key)
        cert.add_extensions(extensions)
        cert.set_version(2)
        cert.sign(self.ca_key, 'sha256')

        return cert, key


class ProxyServer:
    def __init__(self):
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
        context = ssl.create_default_context()
        remote_sock = context.wrap_socket(socket.socket(socket.AF_INET,
                                                        socket.SOCK_STREAM),
                                          server_hostname=host)
        remote_sock.connect((host, port))

        client_sock.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

        #Getting SSL certificate from remote server
        der_cert = remote_sock.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert.encode())

        ssl_generator = SSLGenerator('rootCA.crt', 'rootCA.key')

        new_cert, private_key = ssl_generator.generate_same_cert_as(cert)

        path_to_cert = f'certificates/{host}.crt'
        path_to_key = f'certificates/{host}.key'

        if not os.path.exists(path_to_cert):
            with open(path_to_cert, 'x') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, new_cert).decode())

            with open(path_to_key, 'x') as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key).decode())

        sclient = ssl.wrap_socket(client_sock,
                                  certfile=path_to_cert,
                                  keyfile=path_to_key,
                                  server_side=True,
                                  ssl_version=ssl.PROTOCOL_TLS,
                                  do_handshake_on_connect=False)

        #TODO: Получать данные от клиента порционно и тут же отправлять
        # на сервер
        client_data = sclient.recv(10000)
        print(client_data)
        remote_sock.sendall(client_data)

        while True:
            server_data = remote_sock.recv(1024)

            print('receiving data')
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


def main():
    server = ProxyServer()
    server.start('127.0.0.1', 8787)




def test():
    context = ssl.create_default_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    secure_sock = context.wrap_socket(sock, server_hostname='gist.github.com')
    secure_sock.connect(('gist.github.com', 443))
    der_cert = secure_sock.getpeercert(True)
    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert.encode())

    ssl_generator = SSLGenerator('rootCA.crt', 'rootCA.key')

    new_cert, private_key = ssl_generator.generate_same_cert_as(cert)

    with open('certificates/cert.crt', 'xb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, new_cert))


if __name__ == '__main__':
    main()
