'''
Hui Cui, Robert H.Deng, Guowei Wu, Junzuo Lai
 
| From: "An Efficient and Expressive Ciphertext-Policy Attribute-Based Encryption Scheme with Partially Hidden Access Structures".
| Published in: ProvSec 2016
| type:           Anonymous CP-ABE scheme
| setting:        Type-III pairing

:Authors:    
:Date:       13/12/2023
'''

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.ABEnc import ABEnc, Input, Output
from msp import MSP
import copy
from secretutil import SecretUtil
from policytree import PolicyParser

debug = True

class CDWL16_CP(ABEnc):    
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "CDWL CP-A2BE"
        self.group = group_obj   
        self.util = MSP(self.group, verbose)
        global util
        util = SecretUtil(group_obj)

    def setup(self):
        # Choose group elements
        g_1 = self.group.random(G1)
        g_2 = self.group.random(G2)      
        x1, x2, x3, x4 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        
        u_1 = g_1 ** x1
        u_2 = g_2 ** x1
        
        h_1 = g_1 ** x2
        h_2 = g_2 ** x2
        
        v_1 = g_1 ** x3
        v_2 = g_2 ** x3
        
        w_1 = g_1 ** x4
        w_2 = g_2 ** x4   
                      
        alpha, d1, d2, d3, d4 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)  

        g1 = g_1 ** d1
        g2 = g_1 ** d2
        g3 = g_1 ** d3
        g4 = g_1 ** d4

        e_g1g2_alpha = pair(g_1, g_2) ** alpha
        
        pk = {'g_1': g_1, 'u_1': u_1, 'h_1': h_1, 'v_1': v_1, 'w_1': w_1, 'g1': g1, 'g2': g2, 'g3': g3, 'g4': g4, 'e_g1g2_alpha': e_g1g2_alpha}
        msk = {'g2_alpha': g_2 ** alpha, 'g_2': g_2, 'u_2': u_2, 'h_2': h_2, 'v_2': v_2, 'w_2': w_2, 'd1': d1, 'd2': d2, 'd3': d3, 'd4': d4}
              
        return pk, msk

    def keygen(self, pk, msk, attr_list): 
        # Get attribute names 
        attr_list_name = []
        for attr in attr_list:
            name = attr.split(':')[0] 
            attr_list_name.append(name)    

        r, r_prime = self.group.random(ZR), self.group.random(ZR)    
        
        sk_1 = msk['g2_alpha'] * msk['w_2'] ** (msk['d1'] * msk['d2'] * r + msk['d3'] * msk['d4'] * r_prime)
        sk_2 = msk['g_2'] ** (msk['d1'] * msk['d2'] * r + msk['d3'] * msk['d4'] * r_prime)
                   
        sk_3, sk_4, sk_5, sk_6, sk_7 = {}, {}, {}, {}, {}
        
        for attr in attr_list:
            x = attr_list.index(attr)        
            r1, r2 = self.group.random(ZR), self.group.random(ZR)  
            sk_3[attr_list_name[x]] = msk['g_2'] ** (msk['d1'] * msk['d2'] * r1 + msk['d3'] * msk['d4'] * r2)               
            attrHash = self.group.hash(attr, ZR)  
            tem = msk['u_2'] ** attrHash * msk['h_2']
            tem_1 = tem ** r1 * msk['v_2'] ** (-r)
            tem_2 = tem ** r2 * msk['v_2'] ** (-r_prime)           
            sk_4[attr_list_name[x]] = tem_1 ** msk['d2']
            sk_5[attr_list_name[x]] = tem_1 ** msk['d1']           
            sk_6[attr_list_name[x]] = tem_2 ** msk['d4']
            sk_7[attr_list_name[x]] = tem_2 ** msk['d3']           
         
        sk = {'attr_set_name': attr_list_name, 'sk_1': sk_1, 'sk_2': sk_2, 'sk_3': sk_3, 'sk_4': sk_4, 'sk_5': sk_5, 'sk_6': sk_6, 'sk_7': sk_7}
            
        return sk
   
    def encrypt(self, pk, msg, attr_policy):
        # Get attribute names
        attr_policy = util.createPolicy(attr_policy)   # convert the policy from string to Bin.node format
        policy_name = copy.deepcopy(attr_policy)
    
        parser = PolicyParser()
        parser.policy_strip(policy_name) # remove keyword values in the policy 

        # Use MSP for access policy
        mono_span_prog = self.util.convert_policy_to_msp(attr_policy)
        num_cols = self.util.len_longest_row    

        # pick random shares
        mu = self.group.random() 
        v = [mu]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)      
            
        ct_1 = pk['g_1'] ** mu
        ct_2, ct_3, ct_4, ct_5, ct_6, ct_7 = {}, {}, {}, {}, {}, {}        
            
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attr_name = attr_stripped.split(':')[0]
            attrHash = self.group.hash(attr_stripped, ZR)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))                    
            z, s1, s2 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)     
            ct_2[attr_name] = pk['w_1'] ** Mivtop * pk['v_1'] ** z	    
            ct_3[attr_name] = (pk['u_1'] ** attrHash * pk['h_1']) ** (-z)
            ct_4[attr_name] = pk['g1'] ** s1
            ct_5[attr_name] = pk['g2'] ** (z - s1)
            ct_6[attr_name] = pk['g3'] ** s2
            ct_7[attr_name] = pk['g4'] ** (z - s2)
            
        ct_8 = pk['e_g1g2_alpha'] ** mu * msg
          
        ct = {'policy_name': policy_name, 'ct_1': ct_1, 'ct_2': ct_2, 'ct_3': ct_3, 'ct_4': ct_4, 'ct_5': ct_5, 'ct_6': ct_6, 'ct_7': ct_7, 'ct_8': ct_8}  
                             
        return ct

    def decrypt(self, ct, sk, msg):
        subsets = util.prune(ct['policy_name'], sk['attr_set_name'], 1)
 
        if subsets == False:  
            print('Attribute names are not matching.')
            result = 0 
            return subsets, result
           
        for one_subset in subsets:
            T = (pair(ct['ct_1'], sk['sk_1'])) ** (-1)
            for one_name in one_subset:
                k = one_name.getAttribute()                                       
                B = pair(ct['ct_2'][k], sk['sk_2']) * pair(ct['ct_3'][k], sk['sk_3'][k]) * pair(ct['ct_4'][k], sk['sk_4'][k]) * pair(ct['ct_5'][k], sk['sk_5'][k]) * pair(ct['ct_6'][k], sk['sk_6'][k]) * pair(ct['ct_7'][k], sk['sk_7'][k])
                T *= B

            if msg == ct['ct_8'] * T:     
                result = 1             
                break 
            else:
                result = 0
                continue        
        return subsets, result
