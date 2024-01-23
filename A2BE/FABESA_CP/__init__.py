'''

| From: "FABESA: Fast (and Anonymous) Attribute-Based Encryption with Adaptive Security under Standard Assumption"       
| type:           Anonymous CP-ABE scheme
| setting:        Type-III Pairing

:Authors:         
:Date:            13/12/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from policytree import PolicyParser
from secretutil import SecretUtil
from msp import MSP
import re, numpy, copy

debug = False

class FABESA_CP(ABEnc):         
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "Our CP-A2BE"
        self.group = group_obj
        self.util = MSP(self.group, verbose)
        global util
        util = SecretUtil(self.group)          

    def setup(self):
        # pick parameters
        g_1 = self.group.random(G1)
        g_2 = self.group.random(G2)
        alpha, b_1, b_2 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        e_g1g2 = pair(g_1, g_2)

        # public key and secret key
        pk = {'g_1': g_1, 'g_2': g_2, 'g_2^b_1': g_2 ** b_1, 'g_2^b_2': g_2 ** b_2, 'e_g1g2_a': e_g1g2 ** alpha}
        msk = {'a': alpha, 'b_1': b_1, 'b_2': b_2}

        return pk, msk

    def keygen(self, pk, msk, attr_list):     
        # Get attribute names 
        attr_list_name = []
        for attr in attr_list:
            name = attr.split(':')[0] 
            attr_list_name.append(name)          
        
        r = self.group.random(ZR)

        sk_1 = pk['g_2'] ** r	
        sk_2 = pk['g_1'] ** (msk['a'] - r)
        sk_3 = {}
        sk_4 = {}

        mskt_1 = r/msk['b_1']
        mskt_2 = r/msk['b_2']        
        
        for attr in attr_list:
            x = attr_list.index(attr)
            attr_0 = '0' + attr
            attr_1 = '1' + attr
            attrHash_0 = self.group.hash(attr_0, G1)
            attrHash_1 = self.group.hash(attr_1, G1)
            sk_3[attr_list_name[x]] = attrHash_0 ** mskt_1
            sk_4[attr_list_name[x]] = attrHash_1 ** mskt_2      
                                        
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

        s_1, s_2 = self.group.random(ZR), self.group.random(ZR)
        s = s_1 + s_2

        v = [s]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)
        
        ct_1 = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attr_name_label = attr_stripped.split(':')[0]
            
            attr_stripped_0 = '0' + attr_stripped
            attr_stripped_1 = '1' + attr_stripped
            
            attrHash_0 = self.group.hash(attr_stripped_0, G1)
            attrHash_1 = self.group.hash(attr_stripped_1, G1)
            
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            tep = pk['g_1'] ** Mivtop 
            ct_1[attr_name_label]  = tep * (attrHash_0 ** s_1) * (attrHash_1 * s_2)
        
        ct_2 = pk['g_2'] ** s 
        ct_3 = pk['g_2^b_1'] ** s_1
        ct_4 = pk['g_2^b_2'] ** s_2       
        ct_5 = pk['e_g1g2_a'] ** s * msg
        
        return {'attr_policy_name': attr_policy_name, 'ct_1': ct_1, 'ct_2': ct_2, 'ct_3': ct_3, 'ct_4': ct_4, 'ct_5': ct_5}

    def decrypt(self, ct, sk, msg):
        # Match the attribute names and policy names
        subsets = util.prune(ct['attr_policy_name'], sk['attr_set_name'], 1)
 
        if subsets == False:  
            print('Attribute names are not matching.')
            result = 0 
            return subsets, result
                           
        for one_subset in subsets:
            prod_ct_1 = 1
            prod_sk_3 = 1
            prod_sk_4 = 1

            for one_name in one_subset:
                k = one_name.getAttribute()
                
                for name in ct['ct_1'].keys():
                    if k == name: 
                        prod_ct_1 *= ct['ct_1'][k]                       
                                                                                                                                                
                for name in sk['sk_3'].keys(): 
                    if k == name:
                        prod_sk_3 *= sk['sk_3'][k]                                                 
                
                for name in sk['sk_4'].keys():
                    if k == name:
                        prod_sk_4 *= sk['sk_4'][k]                                         
                                                  
            e1 = pair(prod_ct_1, sk['sk_1'])
            e2 = pair(sk['sk_2'], ct['ct_2'])
            e3 = pair(prod_sk_3, ct['ct_3'])
            e4 = pair(prod_sk_4, ct['ct_4'])           
                           
            if msg == ct['ct_5'] * e3 * e4 / (e1 * e2):     
                result = 1             
                break 
            else:
                result = 0
                continue                                                
        return subsets, result
              
