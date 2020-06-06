from OpenSSL import crypto

class SSLGenerator:
    def __init__(self, path_ca_cert, path_ca_key):
        with open(path_ca_cert) as cert_file:
            with open(path_ca_key) as key_file:
                self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                                       cert_file.read())

                self.ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                                     key_file.read())

    def generate_same_cert_as(self, cert):
        cn = next(cmp for cmp in cert.get_subject().get_components()
                  if cmp[0] == b'CN')[1]
        san = b''

        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                san = str(ext).encode()
                print(san)
                break

        return self.generate_cert_with_cn_san(cn, san)

    def generate_cert_with_cn_san(self, cn, san):
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)

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
        cert.set_pubkey(pkey)
        cert.add_extensions(extensions)
        cert.set_version(2)
        cert.sign(self.ca_key, 'sha256')

        return cert, pkey
