'''
:Date:            12/2023
'''
import re, random
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser

from A2BE.FABESA_CP import FABESA_CP
from A2BE.CDWL16_CP import CDWL16_CP
from A2BE.FEASE_KP import FEASE_KP
from A2BE.FABESA_KP import FABESA_KP
from A2BE.CWDWL17_KP import CWDWL17_KP

def run_kpabe(kpabe, attr_list, attr_policy, msg):
    (pk, msk) = kpabe.setup()
    key = kpabe.keygen(pk, msk, attr_policy)
    ct = kpabe.encrypt(pk, msg, attr_list)
    subsets, result = kpabe.decrypt(pk, ct, key, msg)
    
    if debug:
        if result == 1:
            print("Successful decryption for {}!".format(kpabe.name))
        else:
            print("Decryption failed for {}!".format(kpabe.name))   
        
def run_cpabe(cpabe, attr_list, attr_policy, msg):
    (pk, msk) = cpabe.setup()
    key = cpabe.keygen(pk, msk, attr_list)
    ct = cpabe.encrypt(pk, msg, attr_policy)
    subsets, result = cpabe.decrypt(ct, key, msg)
    
    if debug:
        if result == 1:
            print("Successful decryption for {}!".format(cpabe.name))
        else:
            print("Decryption failed for {}!".format(cpabe.name))   

def wordList_prep(num_words):
    f = open('./words.txt','r')
    lines = f.readlines()
    
    word_list = []
    i = 0
    indices = random.sample(range(1, 466466), num_words)
    for i in indices:
        word = lines[i]
        word = word.split('\n')[0]
        word = word.replace("'", "")
        word = word.replace("-", "")
        word_list.append(word.upper())
    f.close()
    return word_list
    
def create_list_and_policy(n_1, n_2):
    word_list = wordList_prep(n_1)
       
    attr_list = []
    for i in word_list:
        attr = i      
        attr = attr + ':' + str(random.choice(range(1, 3)))
        attr_list.append(attr)

    choice = [' and ', ' or ']
    indices = random.sample(range(len(word_list)), n_2)
     
    attr_policy = ''
    for i, num in enumerate(indices):
        policy_name = word_list[num]        
        k = random.choice(choice)    
        
        if i in range(len(indices) - 1):  
            attr_policy = attr_policy + policy_name + ':' + str(random.choice(range(1, 5))) + '' + k + ''
        else:       
            attr_policy = attr_policy + policy_name + ':' + str(random.choice(range(1, 5)))
            
    return attr_list, attr_policy 
             
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('BN254')
       
    # choose a random message
    msg = pairing_group.random(GT)  
           
    list_size = 5
    policy_size = 2

    attr_list, attr_policy = create_list_and_policy(list_size, policy_size)

# ------------- KP-A2BE schemes ------------------------------------------------------    
    kpabe_1 = FABESA_KP(pairing_group)
    run_kpabe(kpabe_1, attr_list, attr_policy, msg)  
    
    kpabe_2 = CWDWL17_KP(pairing_group)
    run_kpabe(kpabe_2, attr_list, attr_policy, msg)  
    
    kpabe_3 = FEASE_KP(pairing_group)
    run_kpabe(kpabe_3, attr_list, attr_policy, msg)    

# ------------- CP-A2BE schemes ------------------------------------------------------   
    cpabe_1 = FABESA_CP(pairing_group)
    run_cpabe(cpabe_1, attr_list, attr_policy, msg) 
    
    cpabe_2 = CDWL16_CP(pairing_group) 
    run_cpabe(cpabe_2, attr_list, attr_policy, msg) 

if __name__ == "__main__":
    debug = True
    main()
