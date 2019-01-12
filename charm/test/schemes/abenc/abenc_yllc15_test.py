import unittest

from charm.schemes.abenc.abenc_yllc15 import YLLC15
from charm.toolbox.pairinggroup import PairingGroup, GT


class YLLC15Test(unittest.TestCase):

    def setUp(self):
        group = PairingGroup('SS512')
        self.cpabe_scheme = YLLC15(group)
        (self.params, self.msk) = self.cpabe_scheme.setup()

    def test_ukgen(self, user_id='bob@example.com'):
        (public_key, secret_key) = self.cpabe_scheme.ukgen(self.params, user_id)

    def test_proxy_key_gen(self):
        pkcs, skcs = self.cpabe_scheme.ukgen(self.params, "aws@amazonaws.com")
        pku, sku = self.cpabe_scheme.ukgen(self.params, "alice@example.com")
        attribute_list = "A"
        proxy_key_user = self.cpabe_scheme.proxy_keygen(self.params, self.msk, pkcs, pku, attribute_list)

    def test_ciphertext_is_never_equal_to_plaintext(self):
        random_key_elem = self.cpabe_scheme.group.random(GT)
        pol = '((ONE or THREE) and (TWO or FOUR))'
        ciphertext = self.cpabe_scheme.encrypt(self.params, random_key_elem, pol)
        assert ciphertext != random_key_elem


if __name__ == "__main__":
    unittest.main()