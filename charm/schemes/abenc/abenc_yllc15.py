'''

| From: "Extended Proxy-Assisted Approach: Achieving Revocable Fine-Grained Encryption of Cloud Data".
| Published in: 2015
| Available from: 
| Notes: adapted from BSW07
| Security Assumption: 
|
| type:           ciphertext-policy attribute-based encryption
| setting:

:Authors:    D Hellinger
:Date:       11/2018
'''
from charm.toolbox.ABEnc import ABEnc, Output
from charm.toolbox.pairinggroup import ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil

# type annotations
pk_t = {'g': G1, 'g2': G2, 'h': G1, 'f': G1, 'e_gg_alpha': GT}
mk_t = {'beta': ZR, 'g2_alpha': G2}
sk_t = {'D': G2, 'Dj': G2, 'Djp': G1, 'S': str}
ct_t = {'C_tilde': GT, 'C': G1, 'Cy': G1, 'Cyp': G2}

debug = False


class CPabe_YLLC15(ABEnc):
    """
    Possibly a subclass of BSW07?
    """
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj

    @Output(pk_t, mk_t)
    def setup(self):
        g, gp = self.group.random(G1), self.group.random(G2)
        alpha, beta = self.group.random(ZR), self.group.random(ZR)
        # initialize pre-processing for generators
        g.initPP()
        gp.initPP()

        h = g ** beta
        f = g ** ~beta
        e_gg_alpha = pair(g, gp ** alpha)

        pk = {'g': g, 'g2': gp, 'h': h, 'f': f, 'e_gg_alpha': e_gg_alpha}
        mk = {'beta': beta, 'alpha': alpha}
        return (pk, mk)

    def ukgen(self, params, user_id):
        # ripped from pkenc_elgamal85.py
        # x is private, g is public param
        x = self.group.random(ZR)

        g = params['g']
        pk = g ** x
        sk = x
        return pk, sk

    def proxy_keygen(self, params, msk, pkcs, pku, attribute_list):
        r1 = self.group.random(ZR)
        r2 = self.group.random(ZR)
        g = params['g']
        g2 = params['g2']

        k = ((pkcs ** r1) * (pku ** msk['alpha']) * (g ** r2)) ** ~msk['beta']
        k_prime = g ** r1
        k_attrs = {}
        for attr in attribute_list:
            r_attr = self.group.random(ZR)
            k_attr1 = (g ** r2) * (self.group.hash(str(attr), G1) ** r_attr)
            k_attr2 = g2 ** r_attr
            k_attrs[attr] = (k_attr1, k_attr2)

        return {'k': k, 'k_prime': k_prime, 'k_attrs': k_attrs}
