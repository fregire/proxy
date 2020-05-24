from OpenSSL import crypto

class SSLGenerator:
    def __init__(self, path_ca_cert, path_ca_key):
        self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                               open(path_ca_cert).read())

        self.ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                             open(path_ca_key).read())

    def generate_same_cert_as(self, cert):
        cn = list(filter(lambda opt: opt[0] == b'CN',
                  cert.get_subject().get_components()))[0][1]
        san = b''

        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                san += str(ext).encode()

        return self.generate_cert_with_cn_san(cn, san)

    def generate_cert_with_cn_san(self, cn, san):
        # Public Key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Extensions
        extensions = list()
        extensions.append(crypto.X509Extension(b'basicConstraints',
                                               False, f'CA:FALSE'.encode()))
        extensions.append(crypto.X509Extension(b'subjectAltName',
                                               False, san))
        cert = crypto.X509()
        cert.get_subject().CN = cn

        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_pubkey(key)
        cert.add_extensions(extensions)
        cert.set_version(2)
        cert.sign(self.ca_key, 'sha256')

        return cert, key
