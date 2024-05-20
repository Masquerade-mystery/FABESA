'''

| From: "Fast (and Anonymous) Attribute-Based Encryption with Adaptive Security under Standard Assumption"
| Notes: Implemented the scheme in Figure 3
| type:           KP-ABE scheme
| setting:        Type-III Pairing

:Authors:         
:Date:            13/12/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
from policytree import PolicyParser
from secretutil import SecretUtil
import time
import re, numpy, copy
debug = False

class FEASE23KPABE(ABEnc):         
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "FEASE KP-ABE"
        self.group = group_obj
        self.util = MSP(self.group, verbose)     

    def setup(self):
        # pick parameters
        g_1 = self.group.random(G1)
        g_2 = self.group.random(G2)       
        
        a = self.group.random(ZR)
        b_1 = self.group.random(ZR)
        b_2 = self.group.random(ZR)
        e_g1g2 = pair(g_1, g_2)
        
        # public key and secret key
        pk = {'g_1': g_1, 'g_2': g_2, 'g_2^b_1': g_2 ** b_1, 'g_2^b_2': g_2 ** b_2, 'e_g1g2_a': e_g1g2 ** a}
        msk = {'a': a, 'b_1': b_1, 'b_2': b_2}
       
        return pk, msk

    def keygen(self, pk, msk, attr_policy):
        # convert the policy from string to Bin.node format
        policy = self.util.createPolicy(attr_policy)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row
        
        # pick randomness
        r = self.group.random(ZR)
        
        # pick random shares
        v = [msk['a']]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)
        
        sk_1 = pk['g_2'] ** r	
        sk_2 = {}
        sk_3 = {}
        
        skt_1 = 1/msk['b_1']
        skt_2 = 1/msk['b_2']    
        
        #Using MSP
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)         
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            tep = pk['g_1'] ** Mivtop * attrHash ** r
            sk_2[attr] = tep ** skt_1
            sk_3[attr] = tep ** skt_2
                        
        return {'policy': policy, 'sk_1': sk_1, 'sk_2': sk_2, 'sk_3': sk_3} 

    def encrypt(self, pk, msg, attr_list):
        # Pick Randomness
        s_1 = self.group.random(ZR)
        s_2 = self.group.random(ZR)
        s = s_1 + s_2
       
        ct_1 = {}
        for attr in attr_list:
            x = attr_list.index(attr)
            attrHash = self.group.hash(attr, G1)
            ct_1[attr] = attrHash ** s
                
        ct_2 = pk['g_2^b_1'] ** s_1
        ct_3 = pk['g_2^b_2'] ** s_2
        ct_4 = pk['e_g1g2_a'] ** s * msg
        
        return {'attr_list': attr_list, 'ct_1': ct_1, 'ct_2': ct_2, 'ct_3': ct_3, 'ct_4': ct_4}
        
    def decrypt(self, pk, ct, sk):
        # Match the attribute names and policy names
        nodes = self.util.prune(sk['policy'], ct['attr_list'])

        if not nodes:
            print ("Policy not satisfied.")
            result = 0
            return result
              
        prod_ct_1 = 1
        prod_sk_2 = 1
        prod_sk_3 = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
               
            prod_ct_1 *= ct['ct_1'][attr_stripped]  
            prod_sk_2 *= sk['sk_2'][attr]
            prod_sk_3 *= sk['sk_3'][attr]
                                                               
        e1 = pair(prod_ct_1, sk['sk_1'])
        e2 = pair(prod_sk_2, ct['ct_2'])
        e3 = pair(prod_sk_3, ct['ct_3'])       
                                                  
        return ct['ct_4'] * e1 / (e2 * e3)      
              
