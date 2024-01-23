'''
Hui Cui, Zhiguo Wan, Robert H.Deng, Guilin Wang, Yingjiu Li
 
| From: "Efficient and Expressive Keyword Search Over Encrypted Data in Cloud".
| Published in: IEEE Transactions on Dependable and Secure Computing (TDSC) 2016
| type:           Anonymous KP-ABE scheme
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
class CWDWL17_KP(ABEnc):    
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "CWDWL KP-A2BE"
        self.group = group_obj   
        self.util = MSP(self.group, verbose)
        global util
        util = SecretUtil(group_obj)

    def setup(self):
        g_1, g_2 = self.group.random(G1), self.group.random(G2)
        x1, x2, x3 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        
        u_1 = g_1 ** x1
        u_2 = g_2 ** x1
        
        h_1 = g_1 ** x2
        h_2 = g_2 ** x2
        
        w_1 = g_1 ** x3
        w_2 = g_2 ** x3   
        
        alpha, d1, d2, d3, d4 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)  

        g1 = g_1 ** d1
        g2 = g_1 ** d2
        g3 = g_1 ** d3
        g4 = g_1 ** d4

        e_g1g2_alpha = pair(g_1, g_2) ** alpha
        
        pk = {'g_1': g_1, 'u_1': u_1, 'h_1': h_1, 'w_1': w_1, 'g1': g1, 'g2': g2, 'g3': g3, 'g4': g4, 'e_g1g2_alpha': e_g1g2_alpha}
        msk = {'alpha': alpha, 'g_2': g_2, 'u_2': u_2, 'h_2': h_2, 'w_2': w_2, 'd1': d1, 'd2': d2, 'd3': d3, 'd4': d4}
              
        return (pk, msk)

    def keygen(self, pk, msk, policy_str):         
        #print("Debug: policy--->")
        policy = util.createPolicy(policy_str)

        # making a stripped policy tree, removing keyword values
        policy_stripped = copy.deepcopy(policy) 
        parser = PolicyParser()
        parser.policy_strip(policy_stripped)
        
        # Using MSP
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row
        
        # pick random shares
        v = [msk['alpha']]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)        
            
        sk_1, sk_2, sk_3, sk_4, sk_5, sk_6 = {}, {}, {}, {}, {}, {}
        
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            i = attr_stripped.split(':')[0]
            #print(attr_stripped)
            attrHash = self.group.hash(attr_stripped, ZR)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))          
            t1, t2 = self.group.random(ZR), self.group.random(ZR)
            sk_1[i] = msk['g_2'] ** Mivtop * msk['w_2'] ** (msk['d1'] * msk['d2'] * t1 + msk['d3'] * msk['d4'] * t2)           
            sk_2[i] = msk['g_2'] ** (msk['d1'] * msk['d2'] * t1 + msk['d3'] * msk['d4'] * t2)
            sk_3[i] = (msk['u_2'] ** attrHash * msk['h_2']) ** (-msk['d2'] * t1)
            sk_4[i] = (msk['u_2'] ** attrHash * msk['h_2']) ** (-msk['d1'] * t1)
            sk_5[i] = (msk['u_2'] ** attrHash * msk['h_2']) ** (-msk['d4'] * t2)
            sk_6[i] = (msk['u_2'] ** attrHash * msk['h_2']) ** (-msk['d3'] * t2)
         
        sk = {'policy_name': str(policy_stripped), 'sk_1': sk_1, 'sk_2': sk_2, 'sk_3': sk_3, 'sk_4': sk_4, 'sk_5': sk_5, 'sk_6': sk_6}
              
        return sk
   
    def encrypt(self, pk, msg, attr_list):    
        mu = self.group.random(ZR) 
        
        ct_1 = pk['g_1'] ** mu
        
        ct_2, ct_3, ct_4, ct_5, ct_6 = {}, {}, {}, {}, {}
        
        for attr in attr_list:
            z, s1, s2  = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)      
            i = attr.split(':')[0]     
            attrHash = self.group.hash(attr, ZR)
            ct_2[i] = pk['w_1'] ** (-mu) * (pk['u_1'] ** attrHash * pk['h_1']) ** z
            ct_3[i] = pk['g1'] ** (z - s1)
            ct_4[i] = pk['g2'] ** s1
            ct_5[i] = pk['g3'] ** (z - s2)
            ct_6[i] = pk['g4'] ** s2
        
        ct_7 = pk['e_g1g2_alpha'] ** mu * msg
        
        attr_stripped = util.keywords_strip(attr_list)
        
        ct = {'attr_name': str(attr_stripped), 'ct_1': ct_1, 'ct_2': ct_2, 'ct_3': ct_3, 'ct_4': ct_4, 'ct_5': ct_5, 'ct_6': ct_6, 'ct_7': ct_7}
        
        return ct

    def decrypt(self, pk, ct, sk, msg):
        policy = util.createPolicy(sk['policy_name'])        
        pruned_list = util.prune(policy, ct['attr_name'], 1)    
                
        if not pruned_list:
            print ("Attribute names do not match.")
            result = 0 
            return pruned_list, result  
        
        for attr_list in pruned_list:
            T = 1 
            for attr in attr_list:
                #j = i.getAttributeAndIndex(); 
                i = attr.getAttribute() 
                B = pair(ct['ct_1'], sk['sk_1'][i]) * pair(ct['ct_2'][i], sk['sk_2'][i]) * pair(ct['ct_3'][i], sk['sk_3'][i]) * pair(ct['ct_4'][i], sk['sk_4'][i]) * pair(ct['ct_5'][i], sk['sk_5'][i]) * pair(ct['ct_6'][i], sk['sk_6'][i]) 
                T *= B
                
            if msg == ct['ct_7'] / T:
                result = 1
                break
            else:
                result = 0                                              
                continue      
        return pruned_list, result
