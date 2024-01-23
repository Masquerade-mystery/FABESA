'''
Hui Cui, Zhiguo Wan, Robert H.Deng, Guilin Wang, Yingjiu Li
 
| From: "Efficient and Expressive Keyword Search Over Encrypted Data in Cloud".
| Published in: IEEE Transactions on Dependable and Secure Computing (TDSC) 2016
| type:           KP-ABE based PEKS
| setting:        Type-III pairing

:Authors:    
:Date:       27/04/2023
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.ABEnc import ABEnc, Input, Output
from msp import MSP
import copy, time
from secretutil import SecretUtil
from policytree import PolicyParser

debug = True
class KPabe_search(ABEnc):    
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "CuiHui PEKS"
        self.group = group_obj   
        self.util = MSP(self.group, verbose)
        global util
        util = SecretUtil(group_obj)

    def setup(self):
        g, g_hat = self.group.random(G1), self.group.random(G2)
        u, h, w = self.group.random(G1), self.group.random(G1), self.group.random(G1) 
        alpha, d1, d2, d3, d4 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)  

        g1 = g_hat ** d1
        g2 = g_hat ** d2
        g3 = g_hat ** d3
        g4 = g_hat ** d4

        e_gg_alpha = pair(g, g_hat ** alpha)
        
        pk = { 'g':g, 'u':u, 'h':h, 'w':w, 'g_hat':g_hat, 'g1':g1, 'g2':g2, 'g3':g3, 'g4':g4, 'e_gg_alpha':e_gg_alpha }
        msk = {'alpha':alpha, 'd1':d1, 'd2':d2, 'd3':d3, 'd4':d4 }
              
        return (pk, msk)

    def skeygen(self, pk):                    
        gamma = self.group.random(ZR)
        pk_s = pk['g_hat'] ** gamma
        sk_s = gamma     
        
        return pk_s, sk_s

    def trapdoor(self, mk, pk, pk_s, policy_str): 
        
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
        v = [mk['alpha']]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)        

        r = self.group.random(ZR)
        T = pk['g_hat'] ** r
        T1, T2, T3, T4, T5, T6 = {}, {}, {}, {}, {}, {}
        
        for kw, row in mono_span_prog.items():
            kw_stripped = self.util.strip_index(kw)
            k = kw_stripped.split(':')[0]
            kwHash = self.group.hash(kw_stripped, ZR)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))          
            t1, t2 = self.group.random(ZR), self.group.random(ZR)
            T1[k] = pk['g'] ** Mivtop * pk['w']**(mk['d1']*mk['d2']*t1+mk['d3']*mk['d4']*t2)
            T2[k] = pk_s ** r * pk['g_hat']**(mk['d1']*mk['d2']*t1+mk['d3']*mk['d4']*t2) 
            T3[k] = ((pk['u'] ** kwHash * pk['h'])**t1)**(-mk['d2'])
            T4[k] = ((pk['u'] ** kwHash * pk['h'])**t1)**(-mk['d1'])
            T5[k] = ((pk['u'] ** kwHash * pk['h'])**t2)**(-mk['d4'])
            T6[k] = ((pk['u'] ** kwHash * pk['h'])**t2)**(-mk['d3'])
            
        return { 'T':T, 'T1':T1, 'T2':T2, 'T3':T3, 'T4':T4, 'T5':T5, 'T6':T6, 
            'policy':str(policy_stripped) }  
   
    def encrypt(self, pk, W):
        mu = self.group.random() 
        C = pk['e_gg_alpha']**mu
        D = pk['g_hat']**mu
        D_i, E1, E2, F1, F2 = {}, {}, {}, {}, {}
        for i in W:
            z = self.group.random()      # default: ZR
            s1, s2 = self.group.random(ZR), self.group.random(ZR)
            j = i.split(':')[0]     
            D_i[j] = pk['w']**(-mu)*(pk['u']**self.group.hash(i,ZR)*pk['h'])**z
            E1[j] = pk['g1']**(z-s1)
            E2[j] = pk['g2']**(s1)
            F1[j] = pk['g3']**(z-s2)
            F2[j] = pk['g4']**(s2)

        keywords_stripped = util.keywords_strip(W)
        return { 'C':C, 'D':D, 'D_i':D_i, 'E1':E1, 'E2':E2, 'F1':F1, 'F2':F2, 'kws':str(keywords_stripped) }

    def search(self, pk, trap, ct, sk_s):
        #if debug: print("\nTrapdoor's policy: ", trap['policy'])
        start = time.time()

        policy = util.createPolicy(trap['policy'])        
        pruned_list = util.prune(policy, ct['kws'], 1)     
        
        if not pruned_list:
            print ("Keyword names are not satisfied.")
            result = 0 
            return pruned_list, result  
        
        rslt = 0
        num_keywords = 0
        num_tests = 0
        for attr_list in pruned_list:
            #if debug: print("\nKeywords for testing:", attr_list)
            A = 1 
            for i in attr_list:
                j = i.getAttributeAndIndex(); k = i.getAttribute() 
                
                B = ( pair(trap['T1'][k], ct['D']) * pair(ct['D_i'][k], trap['T2'][k]/trap['T']**sk_s) * 
                       pair(trap['T3'][k], ct['E1'][k]) * pair(trap['T4'][k], ct['E2'][k]) * 
                       pair(trap['T5'][k], ct['F1'][k]) * pair(trap['T6'][k], ct['F2'][k]) ) #** z[j]
                A *= B
            num_tests += 1
            num_keywords += len(attr_list)
            if ( A == ct['C'] ):
                result = 1
                break
            else:
                result = 0                                              
                continue      
        end = time.time()
        times = format((end - start) * 1000, '7.2f')   
        print(times)               
        return pruned_list, result
