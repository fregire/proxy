import sys
import os
import unittest
from OpenSSL import crypto
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from modules import ssl_generator
CN = b'anytask.org'
SAN = b'DNS:anytask.org, DNS:www.anytask.org'

class SSLGeneratorTests(unittest.TestCase):
    def test_generating_same_cert(self):
        generator = ssl_generator.SSLGenerator('rootCA.crt', 'rootCA.key')
        cert, pkey = generator.generate_cert_with_cn_san(CN, SAN)

        cn = self.get_cn(cert)
        self.assertEqual(cn, CN)
        self.assertEqual(cert.get_pubkey().bits(), pkey.bits())
        san = self.get_san(cert)
        self.assertEqual(san, SAN)

        copy_cert, copy_key = generator.generate_same_cert_as(cert)
        cn = self.get_cn(copy_cert)
        cn_of_copy = self.get_cn(copy_cert)
        san_of_copy = self.get_san(copy_cert)

        self.assertEqual(cn, cn_of_copy)
        self.assertEqual(san, san_of_copy)

    def get_cn(self, cert):
        return next(cmp for cmp in cert.get_subject().get_components()
                    if cmp[0] == b'CN')[1]

    def get_san(self, cert):
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                return str(ext).encode()

