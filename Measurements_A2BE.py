'''
:Date:            12/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
from policytree import PolicyParser
from secretutil import SecretUtil
from msp import MSP

from A2BE.FABESA_KP import FABESA_KP
from A2BE.FABESA_CP import FABESA_CP
from A2BE.CDWL16_CP import CDWL16_CP
from A2BE.CWDWL17_KP import CWDWL17_KP
from A2BE.FEASE_KP import FEASE_KP

import re, random, copy
import time

#--------------------------------------------------- Measure average time module ----------------------------------------------
def measure_average_times_kpabe(kpabe, attr_list, attr_policy, msg, N=5):   
    sum_setup=0
    sum_enc=0
    sum_keygen=0
    sum_decrypt=0

    for i in range(N):
        # setup time
        start_setup = time.time()
        (pk, msk) = kpabe.setup()
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_setup += time_setup

        # encryption time
        start_enc = time.time()
        ct = kpabe.encrypt(pk, msg, attr_list)
        end_enc = time.time()
        time_enc = end_enc - start_enc
        sum_enc += time_enc

        # keygen time
        start_keygen = time.time()
        key = kpabe.keygen(pk, msk, attr_policy)
        end_keygen = time.time()
        time_keygen = end_keygen - start_keygen
        sum_keygen += time_keygen

        # decryption time
        start_decrypt = time.time()
        subsets, result = kpabe.decrypt(pk, ct, key, msg)
        end_decrypt = time.time()
        time_decrypt = end_decrypt - start_decrypt
        sum_decrypt += time_decrypt       
    
    # compute average time
    time_setup = sum_setup/N
    time_enc = sum_enc/N
    time_keygen = sum_keygen/N
    time_decrypt = sum_decrypt/N

    return [time_setup, time_keygen, time_enc, time_decrypt], subsets 
     
def measure_average_times_cpabe(cpabe, attr_list, attr_policy, msg, N=5):   
    sum_setup=0
    sum_enc=0
    sum_keygen=0
    sum_decrypt=0

    for i in range(N):
        # setup time
        start_setup = time.time()
        (pk, msk) = cpabe.setup()
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_setup += time_setup

        # encryption time
        start_enc = time.time()
        ct = cpabe.encrypt(pk, msg, attr_policy)
        end_enc = time.time()
        time_enc = end_enc - start_enc
        sum_enc += time_enc

        # keygen time
        start_keygen = time.time()
        key = cpabe.keygen(pk, msk, attr_list)
        end_keygen = time.time()
        time_keygen = end_keygen - start_keygen
        sum_keygen += time_keygen

        # decryption time
        start_decrypt = time.time()
        subsets, result = cpabe.decrypt(ct, key, msg)
        end_decrypt = time.time()
        time_decrypt = end_decrypt - start_decrypt
        sum_decrypt += time_decrypt       
    
    # compute average time
    time_setup = sum_setup/N
    time_enc = sum_enc/N
    time_keygen = sum_keygen/N
    time_decrypt = sum_decrypt/N

    return [time_setup, time_keygen, time_enc, time_decrypt], subsets 

#-------------------------------------------------- print running time module -------------------------------------------------
def print_running_time_cpabe(scheme_name, times):
    record = '{:<22}'.format(scheme_name) + format(times[0]*1000, '7.2f') + '   ' + format(times[1]*1000, '7.2f') + '  ' + format(times[2]*1000, '7.2f') + '  ' + format(times[3]*1000, '7.2f')
    print(record)
    return record
    
def print_running_time_kpabe(scheme_name, times):
    record = '{:<22}'.format(scheme_name) + format(times[0]*1000, '7.2f') + '   ' + format(times[1]*1000, '7.2f') + '  ' + format(times[2]*1000, '7.2f') + '  ' + format(times[3]*1000, '7.2f')
    print(record)
    return record    

#-------------------------------------------------- run all module ------------------------------------------------------------
def run_kpabe(pairing_group, attr_list, attr_policy, msg):      
    kpabe_1 = FABESA_KP(pairing_group)
    kpabe_1_times, subsets_1 = measure_average_times_kpabe(kpabe_1, attr_list, attr_policy, msg)   
    
    kpabe_2 = CWDWL17_KP(pairing_group)
    kpabe_2_times, subsets_2 = measure_average_times_kpabe(kpabe_2, attr_list, attr_policy, msg) 
    
    kpabe_3 = FEASE_KP(pairing_group)
    kpabe_3_times, subsets_3 = measure_average_times_kpabe(kpabe_3, attr_list, attr_policy, msg)     
                    
    n1, n2, m, i = get_par(pairing_group, attr_policy, attr_list, subsets_1)
    print('\n')
    print('*'*62)
    print('Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i))
    print('*'*62)
    algos = ['Setup', 'KeyGen', 'Enc', 'Dec']   
    algo_string = 'KP-ABE {:<15}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '      ' + algos[3]
    print('-'*62)
    print(algo_string)
    print('-'*62)
    record_1 = print_running_time_kpabe(kpabe_1.name, kpabe_1_times)     
    record_2 = print_running_time_kpabe(kpabe_2.name, kpabe_2_times)                             
    record_3 = print_running_time_kpabe(kpabe_3.name, kpabe_3_times)         
    print('-'*62)          
   
    with open('Results/New KP-A2BE Results2.txt', 'a') as f:
        f.write('KP-A2BE: ' + 'Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i) + '\n')
        f.write(algo_string + '\n')
        f.write(record_1 + '\n') 
        f.write(record_2 + '\n')       
        f.write(record_3 + '\n')                       
        f.write('\n')     
    open('Results/New KP-A2BE Results2.txt', 'r')  
    with open('Results/New KP-A2BE Results2.txt', 'a') as f:     
        f.write('*' * 62 + '\n')            
    return       
    
    
def run_cpabe(pairing_group, attr_list, attr_policy, msg):      
    cpabe_1 = FABESA_CP(pairing_group)
    cpabe_1_times, subsets_1 = measure_average_times_cpabe(cpabe_1, attr_list, attr_policy, msg)   
    
    cpabe_2 = CDWL16_CP(pairing_group)
    cpabe_2_times, subsets_2 = measure_average_times_cpabe(cpabe_2, attr_list, attr_policy, msg)   
                 
    n1, n2, m, i = get_par(pairing_group, attr_policy, attr_list, subsets_1)
    print('\n')
    print('*'*62)
    print('Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i))
    print('*'*62)
    algos = ['Setup', 'KeyGen', 'Enc', 'Dec']   
    algo_string = 'CP-ABE {:<15}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '      ' + algos[3]
    print('-'*62)
    print(algo_string)
    print('-'*62)
    record_1 = print_running_time_cpabe(cpabe_1.name, cpabe_1_times)     
    record_2 = print_running_time_cpabe(cpabe_2.name, cpabe_2_times)                     
    print('-'*62)          
   
    with open('Results/New CP-A2BE Results2.txt', 'a') as f:
        f.write('CP-A2BE: ' + 'Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i) + '\n')
        f.write(algo_string + '\n')
        f.write(record_1 + '\n') 
        f.write(record_2 + '\n')    
        f.write('\n')     
    open('Results/New CP-A2BE Results2.txt', 'r')  
    with open('Results/New CP-A2BE Results2.txt', 'a') as f:     
        f.write('*' * 62 + '\n')            
    return          

# ------------------------------------------------------ get parameters module ------------------------------------------------
# get parameters of the monotone span program
def get_par(pairing_group, attr_policy, attr_list, subsets):      
    util = SecretUtil(pairing_group) 
    attr_policy = util.createPolicy(attr_policy)   # convert the policy from string to Bin.node format     
     
    msp_obj = MSP(pairing_group)
    mono_span_prog = msp_obj.convert_policy_to_msp(attr_policy)
    
    n1 = len(mono_span_prog) # number of rows
    n2 = msp_obj.len_longest_row # number of columns
    m = len(attr_list) # number of keywords  
    i = len(subsets)

    return n1, n2, m, i

# -------------------------------------------------- Main functions module ---------------------------------------------------    
def wordList_prep(num_words):
    ## Open the file with read only permit
    f = open('./words.txt','r')
    lines = f.readlines()
    
    word_list = []
    i = 0
    indices = random.sample(range(1, 400000), num_words)
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
        attr = attr + ':' + str(random.choice(range(1, 1000)))
        attr_list.append(attr)

    choice = [' and ', ' or ']
    indices = random.sample(range(len(word_list)), n_2)
     
    attr_policy = ''
    for i, num in enumerate(indices):
        policy_name = word_list[num]        
        k = random.choice(choice)    
        
        if i in range(len(indices) - 1):  
            attr_policy = attr_policy + policy_name + ':' + str(random.choice(range(1, 1000))) + '' + ' AND ' + ''
        else:       
            attr_policy = attr_policy + policy_name + ':' + str(random.choice(range(1, 1000)))
            
    return attr_list, attr_policy
                  
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
    
    # choose a random message
    msg = pairing_group.random(GT)
    
    list_size = [100]
    policy_size = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    
    for size_p in policy_size:
        for size_k in list_size:
            attr_list, attr_policy = create_list_and_policy(size_k, size_p)
            #run_kpabe(pairing_group, attr_list, attr_policy, msg)
            run_cpabe(pairing_group, attr_list, attr_policy, msg)
      
if __name__ == "__main__":
    debug = True
    main()                 
           
