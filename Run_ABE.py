'''
:Date:            12/2023
'''
import re, random
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser

from ABE.FABESA_CP import FABESA_CP
from ABE.FAME_CP import AC17CPABE
from ABE.FABEO_CP import FABEO22CPABE
from ABE.cgw15cp import CGW15CPABE
from ABE.abgw17cp import ABGW17CPABE
from ABE.bsw07cp import BSW07CPABE
from ABE.waters11cp import Waters11CPABE

from ABE.FABESA_KP import FABESA_KP
from ABE.FAME_KP import AC17KPABE
from ABE.FABEO_KP import FABEO22KPABE
from ABE.cgw15kp import CGW15KPABE
from ABE.gpsw06kp import GPSW06KPABE
from ABE.abgw17kp import ABGW17KPABE

def run_kpabe(kpabe, attr_list, attr_policy, msg):
    (pk, msk) = kpabe.setup()
    sk = kpabe.keygen(pk, msk, attr_policy)
    ct = kpabe.encrypt(pk, msg, attr_list)
    rec_msg = kpabe.decrypt(pk, ct, sk)
    
    if debug:
        if rec_msg == msg:
            print("Successful decryption for {}.".format(kpabe.name))
        else:
            print("Decryption failed for {}.".format(kpabe.name))
  
def run_cpabe(cpabe, attr_list, attr_policy, msg):
    (pk, msk) = cpabe.setup()
    sk = cpabe.keygen(pk, msk, attr_list)
    ct = cpabe.encrypt(pk, msg, attr_policy)
    rec_msg = cpabe.decrypt(pk, ct, sk)
    
    if debug:
        if rec_msg == msg:
            print("Successful decryption for {}.".format(cpabe.name))
        else:
            print("Decryption failed for {}.".format(cpabe.name))
             
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
       
    # choose a random message
    msg = pairing_group.random(GT)  
                
    attr_list = ['1', '2', '3', '4', '5']
    policy_str = '((1 and 2) and (3 OR 4))'    
    

# ------------- KP-ABE schemes ------------------------------------------------------    
    fabesa24_kp = FABESA_KP(pairing_group)
    run_kpabe(fabesa24_kp, attr_list, policy_str, msg)
    
    gpsw06_kp = GPSW06KPABE(pairing_group, 10)
    run_kpabe(gpsw06_kp, attr_list, policy_str, msg)

    cgw15_kp = CGW15KPABE(pairing_group, 2, 10)
    run_kpabe(cgw15_kp, attr_list, policy_str, msg)

    abgw17_kp = ABGW17KPABE(pairing_group)
    run_kpabe(abgw17_kp, attr_list, policy_str, msg)
    
    ac17_kp = AC17KPABE(pairing_group, 2)
    run_kpabe(ac17_kp, attr_list, policy_str, msg)

    fabeo22_kp = FABEO22KPABE(pairing_group)
    run_kpabe(fabeo22_kp, attr_list, policy_str, msg)     
      
 
# ------------- CP-ABE schemes ------------------------------------------------------   
    fabesa24_cp = FABESA_CP(pairing_group)    
    run_cpabe(fabesa24_cp, attr_list, policy_str, msg)
    
    bsw07_cp = BSW07CPABE(pairing_group)
    run_cpabe(bsw07_cp, attr_list, policy_str, msg)

    waters11_cp = Waters11CPABE(pairing_group, 10)
    run_cpabe(waters11_cp, attr_list, policy_str, msg)

    cgw15_cp = CGW15CPABE(pairing_group, 2, 10)
    run_cpabe(cgw15_cp, attr_list, policy_str, msg)

    abgw17_cp = ABGW17CPABE(pairing_group)
    run_cpabe(abgw17_cp, attr_list, policy_str, msg)

    ac17_cp = AC17CPABE(pairing_group, 2)
    run_cpabe(ac17_cp, attr_list, policy_str, msg)
   
    fabeo22_cp = FABEO22CPABE(pairing_group)
    run_cpabe(fabeo22_cp, attr_list, policy_str, msg)
        
     
if __name__ == "__main__":
    debug = True
    main()
