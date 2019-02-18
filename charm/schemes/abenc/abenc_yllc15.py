"""
Yanjiang Yang, Joseph K Liu, Kaitai Liang, Kim Kwang Raymond Choo, Jianying Zhou

| From: "Extended Proxy-Assisted Approach: Achieving Revocable Fine-Grained Encryption of Cloud Data".
| Published in: 2015
| Available from:
| Notes: adapted from BSW07
| Security Assumption:
|
| type:           ciphertext-policy attribute-based encryption
| setting:

:Authors:    Douglas Hellinger
:Date:       11/2018
"""
from typing import Dict

from charm.toolbox.ABEnc import ABEnc, Output
from charm.toolbox.pairinggroup import ZR, G1, G2, GT, pair
from charm.toolbox.schemebase import Input
from charm.toolbox.secretutil import SecretUtil

# type annotations

pk_t = {'g': G1, 'g2': G2, 'h': G1, 'f': G1, 'e_gg_alpha': GT}
mk_t = {'beta': ZR, 'alpha': ZR}
pk_u_t = G1
sk_u_t = ZR
sk_t = {'k': G1, 'k_prime': G1, 'k_attrs': Dict}
ct_t = {'policy_str': str,
        'C': GT,
        'C_prime': G1,
        'C_prime_prime': G1,
        'c_attrs': Dict
        }
v_t = {'C': GT,
       'e_term': GT}

debug = False


class YLLC15(ABEnc):
    """
    Possibly a subclass of BSW07?
    """
    def __init__(self, group):
        ABEnc.__init__(self)
        self.group = group
        self.util = SecretUtil(self.group)

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

    @Input(pk_t)
    @Output(pk_u_t, sk_u_t)
    def ukgen(self, params, user_id):
        # ripped from pkenc_elgamal85.py
        # x is private, g is public param
        x = self.group.random(ZR)

        g = params['g']
        pk_u = g ** x
        sk_u = x
        return pk_u, sk_u

    @Input(pk_t, mk_t, pk_u_t, pk_u_t, [str])
    # @Output(sk_t)
    def proxy_keygen(self, params, msk, pkcs, pku, attribute_list):
        r1 = self.group.random(ZR)
        r2 = self.group.random(ZR)
        g = params['g']

        k = ((pkcs ** r1) * (pku ** msk['alpha']) * (g ** r2)) ** ~msk['beta']
        k_prime = g ** r1
        k_attrs = {}
        for attr in attribute_list:
            r_attr = self.group.random(ZR)
            k_attr1 = (g ** r2) * (self.group.hash(str(attr), G1) ** r_attr)
            k_attr2 = g ** r_attr
            k_attrs[attr] = (k_attr1, k_attr2)

        return {'k': k, 'k_prime': k_prime, 'k_attrs': k_attrs}

    @Input(pk_t, GT, str)
    # @Output(ct_t)
    def encrypt(self, params, msg, policy_str):
        """
         Encrypt a message M under a policy string.

         policy_str must use parentheses e.g. (A) and (B)
        """
        policy = self.util.createPolicy(policy_str)
        s = self.group.random(ZR)
        shares = self.util.calculateSharesDict(s, policy)

        C = (params['e_gg_alpha'] ** s) * msg
        C_prime = params['h'] ** s
        C_prime_prime = params['g'] ** s

        c_attrs = {}
        for attr in shares.keys():
            attr_stripped = self.util.strip_index(attr)
            c_i1 = params['g'] ** shares[attr]
            c_i2 = self.group.hash(attr_stripped, G1) ** shares[attr]
            c_attrs[attr] = (c_i1, c_i2)

        ciphertext = {'policy_str': policy_str,
                      'C': C,
                      'C_prime': C_prime,
                      'C_prime_prime': C_prime_prime,
                      'c_attrs': c_attrs}
        return ciphertext

    # @Input(pk_t, sk_u_t, sk_t, ct_t)
    @Output(v_t)
    def proxy_decrypt(self, params, skcs, proxy_key_user, ciphertext):
        policy_root_node = ciphertext['policy_str']
        k = proxy_key_user['k']
        k_prime = proxy_key_user['k_prime']
        c_prime = ciphertext['C_prime']
        c_prime_prime = ciphertext['C_prime_prime']
        c_attrs = ciphertext['c_attrs']
        k_attrs = proxy_key_user['k_attrs']

        policy = self.util.createPolicy(policy_root_node)
        attributes = proxy_key_user['k_attrs'].keys()
        pruned_list = self.util.prune(policy, attributes)
        if not pruned_list:
            return None
        z = self.util.getCoefficients(policy)
        # reconstitute the policy random secret (A) which was used to encrypt the message
        A = 1
        for i in pruned_list:
            attr = i.getAttributeAndIndex();
            A *= (pair(c_attrs[attr][0], k_attrs[attr][0]) / pair(k_attrs[attr][1], c_attrs[attr][1])) ** z[attr]

        e_k_c_prime = pair(k, c_prime)
        denominator = (pair(k_prime, c_prime_prime) ** skcs) * A
        encrypted_element_for_user_pkenc_scheme = e_k_c_prime / denominator

        intermediate_value = {'C': ciphertext['C'],
                              'e_term': encrypted_element_for_user_pkenc_scheme}

        return intermediate_value

    @Input(pk_t, sk_u_t, v_t)
    @Output(GT)
    def decrypt(self, params, sku, intermediate_value):
        ciphertext = intermediate_value['C']
        e_term = intermediate_value['e_term']
        denominator = e_term ** (sku ** -1)
        msg = ciphertext / denominator
        return msg
