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
from charm.toolbox.msp import MSP
from charm.toolbox.node import BinNode
from charm.toolbox.pairinggroup import ZR, G1, G2, GT, pair

# type annotations
pk_t = {'g': G1, 'g2': G2, 'h': G1, 'f': G1, 'e_gg_alpha': GT}
mk_t = {'beta': ZR, 'g2_alpha': G2}
sk_t = {'D': G2, 'Dj': G2, 'Djp': G1, 'S': str}
ct_t = {'C_tilde': GT, 'C': G1, 'Cy': G1, 'Cyp': G2}

debug = False


class YLLC15(ABEnc):
    """
    Possibly a subclass of BSW07?
    """
    def __init__(self, group):
        ABEnc.__init__(self)
        self.group = group
        self.util = MSP(self.group, verbose=False)

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
        return pk, mk

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

    def encrypt(self, params, msg, policy_str):
        """
         Encrypt a message M under a policy string.

         policy_str must use parentheses e.g. (A) and (B)
        """
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        u = []
        for i in range(num_cols):
            rand = self.group.random(ZR)
            u.append(rand)
        s = u[0]    # shared secret

        C = (params['e_gg_alpha'] ** s) * msg
        C_prime = params['h'] ** s
        C_prime_prime = params['g'] ** s

        c_attrs = {}
        for attr, row in mono_span_prog.items():
            cols = len(row)
            sum = 0
            for i in range(cols):
                sum += row[i] * u[i]
            attr_stripped = self.util.strip_index(attr)
            c_i1 = params['g2'] ** sum
            c_i2 = self.group.hash(str(attr_stripped), G1) ** sum
            c_attrs[attr] = (c_i1, c_i2)

        ciphertext = {'policy': policy,
                      'C': C,
                      'C_prime': C_prime,
                      'C_prime_prime': C_prime_prime,
                      'c_attrs': c_attrs}
        return ciphertext

    def proxy_decrypt(self, params, skcs, proxy_key_user, ciphertext):
        policy_root_node = ciphertext['policy']
        f_rt = decrypt_node(policy_root_node, proxy_key_user, ciphertext)
        if not f_rt:
            return None

        k = proxy_key_user['k']
        c_prime = ciphertext['C_prime']
        e_k_c_prime = pair(k, c_prime)

        k_prime = proxy_key_user['k_prime']
        c_prime_prime = ciphertext['C_prime_prime']
        denominator = (pair(k_prime, c_prime_prime) ** skcs) * f_rt

        user_e_term = e_k_c_prime / denominator

        intermediate_value = {'C': ciphertext['C'],
                              'e_term': user_e_term}

        return intermediate_value

    def decrypt(self, params, sku, intermediate_value):
        ciphertext = intermediate_value['C']
        e_term = intermediate_value['e_term']
        denominator = e_term ** (sku ** -1)
        msg = ciphertext / denominator
        return msg


def decrypt_node(node: BinNode, proxy_key_user, ciphertext):
    sn = set()
    attr = node.getAttribute()
    if attr:
        if attr not in proxy_key_user['k_attrs']:
            return None
        else:
            (k_attr1, k_attr2) = proxy_key_user['k_attrs'][attr]
            (c_attr1, c_attr2) = ciphertext['c_attrs'][attr]
            fn = pair(k_attr1, c_attr1) / pair(k_attr2, c_attr2)
            return fn
    else:
        fch_l = decrypt_node(node.left, proxy_key_user, ciphertext)
        fch_r = decrypt_node(node.right, proxy_key_user, ciphertext)
        if fch_l:
            sn.add(fch_l)
        if fch_r:
            sn.add(fch_r)

        if not sn:
            return None

        fn = 1
        return fn
