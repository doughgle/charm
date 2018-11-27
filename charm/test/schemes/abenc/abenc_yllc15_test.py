import unittest

from charm.schemes.abenc.abenc_yllc15 import CPabe_YLLC15
from charm.toolbox.pairinggroup import PairingGroup


class CPabe_YLLC15Test(unittest.TestCase):

    def setUp(self):
        group = PairingGroup('SS512')
        self.cpabe_scheme = CPabe_YLLC15(group)

    def test_setup(self):
        (params, msk) = self.cpabe_scheme.setup()

    def test_ukgen(self, user_id='bob@example.com'):
        (params, msk) = self.cpabe_scheme.setup()
        (public_key, secret_key) = self.cpabe_scheme.ukgen(params, user_id)

    def test_proxy_key_gen(self):
        (params, msk) = self.cpabe_scheme.setup()
        pkcs, skcs = self.cpabe_scheme.ukgen(params, "aws@amazonaws.com")
        pku, sku = self.cpabe_scheme.ukgen(params, "alice@example.com")
        attribute_list = "A"
        proxy_key_user = self.cpabe_scheme.proxy_keygen(params, msk, pkcs, pku, attribute_list)


if __name__ == "__main__":
    unittest.main()