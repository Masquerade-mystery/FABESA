'''
Zhishuo Zhang, Wei Zhang, Hanxiang Zhuang, Yu Sun, and Zhiguang Qin

| From: "Efficient Partially Policy-Hidden CP-ABE for IoT Assisted Smart Health"
| Published in: 2021
| Notes: Implemented an asymmetric version of the scheme
| Security Assumption: Decisional Parallel Bilinear Diffie-Hellman Exponent
|
| type:           Anonymous Ciphertext-Policy Attribute-Based Encryption
| setting:        Pairing

:Authors:         
:Date:            10/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from policytree import PolicyParser
from secretutil import SecretUtil
from msp import MSP

debug = False


class ZZZSQ21(ABEnc):

    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "ZZZSQ21 CPA2BE"
        self.group = group_obj
        self.util = MSP(self.group, verbose)
        global util
        util = SecretUtil(self.group)    

    def setup(self):
        # pick a random element each from two source groups and pair them
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        alpha, b, d, y, k = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        
        g1_alpha = g1 ** alpha
        g1_b = g1 ** b
        g2_d = g2 ** d
        g2_y = g2 ** y
        e_g1g2_alpha = pair(g1_alpha, g2)
       
        pk = {'g1': g1, 'g2': g2, 'g1_b': g1_b, 'g2_d': g2_d, 'g2_y': g2_y, 'e_g1g2_alpha': e_g1g2_alpha}
        msk = {'g1_alpha': g1_alpha, 'b': b, 'd': d, 'y': y, 'k': k}
        return pk, msk

    def keygen(self, pk, msk, attr_list):
        attr_list_name = []
        for attr in attr_list:
            name = attr.split(':')[0] 
            attr_list_name.append(name) 

        t = self.group.random(ZR)
        
        sk_1 = msk['g1_alpha'] * pk['g1_b'] ** (msk['k'] * msk['d'] * t)
        sk_2 = pk['g2_d'] ** (msk['k'] * t)
        sk_3 = {}     
        sk_4 = {}
           
        for attr in attr_list:
            x = attr_list.index(attr)
            attrHash = self.group.hash(attr, G1)
            sk_3[attr_list_name[x]] = attrHash ** (msk['k'] * t) 
            sk_4[attr_list_name[x]] = attrHash ** msk['y']
            
        return {'attr_set_name': attr_list_name, 'sk_1': sk_1, 'sk_2': sk_2, 'sk_3': sk_3, 'sk_4': sk_4}

    def encrypt(self, pk, msg, attr_policy):
        # Get attribute names
        attr_policy = util.createPolicy(attr_policy)   # convert the policy from string to Bin.node format

        # Use MSP for access policy        
        mono_span_prog = self.util.convert_policy_to_msp(attr_policy)
        num_cols = self.util.len_longest_row
        
        attr_policy_name = attr_policy
    
        parser = PolicyParser()
        parser.policy_strip(attr_policy_name) # remove attribute values in the policy

        s, r_prime = self.group.random(ZR), self.group.random(ZR)  
 
        v = [s]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)
           
        ct_1 = pk['g2'] ** s
        ct_2 = {}
        ct_3 = {}
        ct_5 = {}
        
        tep = pk['g2_y'] ** r_prime
        
        for attr, row in mono_span_prog.items():
            r = self.group.random(ZR)
            attr_stripped = self.util.strip_index(attr)
            attr_name_label = attr_stripped.split(':')[0]                  
            attrHash = self.group.hash(attr_stripped, G1)            
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            ct_2[attr_name_label] = pk['g1_b'] ** Mivtop * attrHash ** (-r)
            ct_3[attr_name_label] = pk['g2_d'] ** r
            ct_5[attr_name_label] = pair(attrHash, tep)
            
        ct_4 = pk['g2'] ** r_prime
        ct_6 = pk['e_g1g2_alpha'] ** s * msg

        return {'attr_policy_name': attr_policy_name, 'ct_1': ct_1, 'ct_2': ct_2, 'ct_3': ct_3, 'ct_4': ct_4, 'ct_5': ct_5, 'ct_6': ct_6}

    def decrypt(self, ct, sk, msg):
        # match the attribute value first and contain a list with all attribute names
        matching_list = []
        for sk4_name, sk4_value in sk['sk_4'].items():
            if pair(sk4_value, ct['ct_4']) in ct['ct_5'].values():
                matching_list.append(sk4_name)    
            else:
                continue
        
        subsets = util.prune(ct['attr_policy_name'], matching_list, 1)
 
        if subsets == False:  
            #print('Attribute names are not matching.')
            result = 0 
            return subsets, result  
                  
        for one_subset in subsets:
            T = pair(sk['sk_1'], ct['ct_1']) ** (-1)
            for one_name in one_subset:
                k = one_name.getAttribute()
                B = pair(ct['ct_2'][k], sk['sk_2']) * pair(sk['sk_3'][k], ct['ct_3'][k])   
                T *= B
            if msg == ct['ct_6'] * T:     
                result = 1             
                break 
            else:
                result = 0
                continue                   
        return subsets, result
