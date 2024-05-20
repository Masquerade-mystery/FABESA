'''
:Date:            12/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
from policytree import PolicyParser
from secretutil import SecretUtil
from msp import MSP

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
from ABE.FEASE_KP import FEASE23KPABE
from ABE.cgw15kp import CGW15KPABE
from ABE.gpsw06kp import GPSW06KPABE
from ABE.abgw17kp import ABGW17KPABE

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
        result = kpabe.decrypt(pk, ct, key)
        end_decrypt = time.time()
        time_decrypt = end_decrypt - start_decrypt
        sum_decrypt += time_decrypt       
    
    # compute average time
    time_setup = sum_setup/N
    time_enc = sum_enc/N
    time_keygen = sum_keygen/N
    time_decrypt = sum_decrypt/N

    return [time_setup, time_keygen, time_enc, time_decrypt]

     
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
        result = cpabe.decrypt(pk, ct, key)
        end_decrypt = time.time()
        time_decrypt = end_decrypt - start_decrypt
        sum_decrypt += time_decrypt       
    
    # compute average time
    time_setup = sum_setup/N
    time_enc = sum_enc/N
    time_keygen = sum_keygen/N
    time_decrypt = sum_decrypt/N

    return [time_setup, time_keygen, time_enc, time_decrypt]

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
def run_kpabe(pairing_group, attr_list, policy_str, msg):  
    feabe23_kp = FABESA_KP(pairing_group)
    feabe23_kp_times = measure_average_times_kpabe(feabe23_kp, attr_list, policy_str, msg)
    
    gpsw06_kp = GPSW06KPABE(pairing_group, 100)
    gpsw06_kp_times = measure_average_times_kpabe(gpsw06_kp, attr_list, policy_str, msg)

    cgw15_kp = CGW15KPABE(pairing_group, 2, 100)
    cgw15_kp_times = measure_average_times_kpabe(cgw15_kp, attr_list, policy_str, msg)

    abgw17_kp = ABGW17KPABE(pairing_group)
    abgw17_kp_times = measure_average_times_kpabe(abgw17_kp, attr_list, policy_str, msg)
    
    ac17_kp = AC17KPABE(pairing_group, 2)
    ac17_kp_times = measure_average_times_kpabe(ac17_kp, attr_list, policy_str, msg)

    fabeo22_kp = FABEO22KPABE(pairing_group)
    fabeo22_kp_times = measure_average_times_kpabe(fabeo22_kp, attr_list, policy_str, msg)
    
    fease23_kp = FEASE23KPABE(pairing_group)
    fease23_kp_times = measure_average_times_kpabe(fease23_kp, attr_list, policy_str, msg)    
                        
    n1, n2, m, i = get_par(pairing_group, policy_str, attr_list)
    print('\n')
    print('*'*62)
    print('Running times (ms) curve BN254: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i))
    print('*'*62)
    algos = ['Setup', 'KeyGen', 'Enc', 'Dec']   
    algo_string = 'KP-ABE {:<15}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '      ' + algos[3]
    print('-'*62)
    print(algo_string)
    print('-'*62)
    record_1 = print_running_time_kpabe(feabe23_kp.name, feabe23_kp_times)     
    record_2 = print_running_time_kpabe(gpsw06_kp.name, gpsw06_kp_times)    
    record_3 = print_running_time_kpabe(cgw15_kp.name, cgw15_kp_times)    
    record_4 = print_running_time_kpabe(abgw17_kp.name, abgw17_kp_times) 
    record_5 = print_running_time_kpabe(ac17_kp.name, ac17_kp_times)                                
    record_6 = print_running_time_kpabe(fabeo22_kp.name, fabeo22_kp_times)   
    record_7 = print_running_time_kpabe(fease23_kp.name, fease23_kp_times)       
    print('-'*62)          
   
    with open('Results/KP-ABE - BN254.txt', 'a') as f:
        f.write('KP-ABE: ' + 'Running times (ms) curve BN254: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i) + '\n')
        f.write(algo_string + '\n')
        f.write(record_1 + '\n') 
        f.write(record_2 + '\n') 
        f.write(record_3 + '\n')         
        f.write(record_4 + '\n')     
        f.write(record_5 + '\n')
        f.write(record_6 + '\n')  
        f.write(record_7 + '\n')             
        f.write('\n')     
    open('Results/KP-ABE - BN254.txt', 'r')  
    with open('Results/KP-ABE - BN254.txt', 'a') as f:     
        f.write('*' * 62 + '\n')            
    return       
    
def run_cpabe(pairing_group, attr_list, policy_str, msg):     
    feabe23_cp = FABESA_CP(pairing_group)  
    feabe23_cp_times = measure_average_times_cpabe(feabe23_cp, attr_list, policy_str, msg)  
    
    bsw07_cp = BSW07CPABE(pairing_group)
    bsw07_cp_times = measure_average_times_cpabe(bsw07_cp, attr_list, policy_str, msg)
    
    waters11_cp = Waters11CPABE(pairing_group, 100)
    waters11_cp_times = measure_average_times_cpabe(waters11_cp, attr_list, policy_str, msg)

    cgw15_cp = CGW15CPABE(pairing_group, 2, 100)
    cgw15_cp_times = measure_average_times_cpabe(cgw15_cp, attr_list, policy_str, msg)

    abgw17_cp = ABGW17CPABE(pairing_group)
    abgw17_cp_times = measure_average_times_cpabe(abgw17_cp, attr_list, policy_str, msg)

    ac17_cp = AC17CPABE(pairing_group, 2)
    ac17_cp_times = measure_average_times_cpabe(ac17_cp, attr_list, policy_str, msg)
   
    fabeo22_cp = FABEO22CPABE(pairing_group)
    fabeo22_cp_times = measure_average_times_cpabe(fabeo22_cp, attr_list, policy_str, msg)  
          
    #n1, n2, m, i = get_par(pairing_group, attr_policy_1, attr_list_1, subsets_1)
    n1, n2, m, i = get_par(pairing_group, policy_str, attr_list)
    print('\n')
    print('*'*62)
    print('Running times (ms) curve BN254: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i))
    print('*'*62)
    algos = ['Setup', 'KeyGen', 'Enc', 'Dec']   
    algo_string = 'CP-ABE {:<15}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '      ' + algos[3]
    print('-'*62)
    print(algo_string)
    print('-'*62)
    record_1 = print_running_time_cpabe(feabe23_cp.name, feabe23_cp_times)     
    record_2 = print_running_time_cpabe(bsw07_cp.name, bsw07_cp_times)    
    record_3 = print_running_time_cpabe(waters11_cp.name, waters11_cp_times)     
    record_4 = print_running_time_cpabe(cgw15_cp.name, cgw15_cp_times)      
    record_5 = print_running_time_cpabe(abgw17_cp.name, abgw17_cp_times)    
    record_6 = print_running_time_cpabe(ac17_cp.name, ac17_cp_times)   
    record_7 = print_running_time_cpabe(fabeo22_cp.name, fabeo22_cp_times)                 
         
    print('-'*62)          
   
    with open('Results/CP-ABE - BN254.txt', 'a') as f:
        f.write('CP-ABE: ' + 'Running times (ms) curve BN254: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i) + '\n')
        f.write(algo_string + '\n')
        f.write(record_1 + '\n') 
        f.write(record_2 + '\n') 
        f.write(record_3 + '\n') 
        f.write(record_4 + '\n')           
        f.write(record_5 + '\n')    
        f.write(record_6 + '\n')
        f.write(record_7 + '\n')  
        f.write('\n')     
    open('Results/CP-ABE - BN254.txt', 'r')  
    with open('Results/CP-ABE - BN254.txt', 'a') as f:     
        f.write('*' * 62 + '\n')            
    return          

# ------------------------------------------------------ get parameters module ------------------------------------------------
def get_par(pairing_group, policy_str, attr_list):   
    msp_obj = MSP(pairing_group)
    policy = msp_obj.createPolicy(policy_str)
    mono_span_prog = msp_obj.convert_policy_to_msp(policy)
    nodes = msp_obj.prune(policy, attr_list)

    n1 = len(mono_span_prog) # number of rows
    n2 = msp_obj.len_longest_row # number of columns
    m = len(attr_list) # number of attributes
    i = len(nodes) # number of attributes in decryption

    return n1, n2, m, i

# -------------------------------------------------- Main functions module ---------------------------------------------------    
def create_policy_string_and_attribute_list(n):
    policy_string = '(1'
    attr_list = ['1']
    for i in range(2,n+1):
        policy_string += ' and ' + str(i)
        attr1 = str(i)
        attr_list.append(attr1)
    policy_string += ')'

    return policy_string, attr_list    
                  
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('BN254')
    
    # choose a random message
    msg = pairing_group.random(GT)
    
    policy_sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    for policy_size in policy_sizes:
        policy_str, attr_list = create_policy_string_and_attribute_list(policy_size)
        run_kpabe(pairing_group, attr_list, policy_str, msg)
        #run_cpabe(pairing_group, attr_list, policy_str, msg) 
    
if __name__ == "__main__":
    debug = True
    main()                 
           
