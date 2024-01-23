from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
from policytree import PolicyParser
from secretutil import SecretUtil
import time

import re, numpy, copy

group = PairingGroup('SS512')

sum_time = 0       
for i in range(10):
    start = time.time()

    g_1 = group.random(G1)
    
    end = time.time()
    time_1 = end - start
    sum_time += time_1
    
times = sum_time/10

print('Choose a generator from G1:', format(times * 1000, '7.2f'))
with open('Results/Test.txt', 'a') as f:
    f.write('Choose a generator from G1:' + format(times * 1000, '7.2f'))
    f.write('\n')         

sum_time = 0
for i in range(10):
    start = time.time()

    g_2 = group.random(G2)  
  
    end = time.time()
    time_1 = end - start    
    sum_time += time_1
    
times = sum_time/10    
print('Choose a generator from G2:', format(times * 1000, '7.2f'))
with open('Results/Test.txt', 'a') as f:
    f.write('Choose a generator from G2:' + format(times * 1000, '7.2f'))
    f.write('\n')
    
sum_time = 0
for i in range(10):       
    start = time.time()

    a = group.random(ZR)

    end = time.time()
    time_1 = end - start
    sum_time += time_1
    
times = sum_time/10        
print('Choose a random number from ZR:', format(times * 1000, '7.2f'))  
with open('Results/Test.txt', 'a') as f:
    f.write('Choose a random number from ZR:' + format(times * 1000, '7.2f'))
    f.write('\n')
    
sum_time = 0
for i in range(10):  
    a, b = group.random(ZR), group.random(ZR)
    
    pk1 = g_1 ** a
    pk2 = g_2 ** b

    start = time.time()

    e_g1g2 = pair(pk1, pk2)

    end = time.time()
    time_1 = end - start
    sum_time += time_1    

times = sum_time/10   
print(g_1)
print(g_2)  
print(pk2)
print(e_g1g2)
print('Calculate a pairing G1 x G2 -> GT:', format(times * 1000, '7.2f')) 
with open('Results/Test.txt', 'a') as f:
    f.write('Calculate a pairing G1 x G2 -> GT:' + format(times * 1000, '7.2f')) 
    f.write('\n')
    
sum_time = 0
for i in range(10):  
    start = time.time()

    pk_1 = g_1 ** a
 
    end = time.time()
    time_1 = end - start
    sum_time += time_1 
    
times = sum_time/10       
print('Calculate an exponentiation on G1:', format(times * 1000, '7.2f'))  
with open('Results/Test.txt', 'a') as f:
    f.write('Calculate an exponentiation on G1:' + format(times * 1000, '7.2f')) 
    f.write('\n')
    
sum_time = 0
for i in range(10): 
    start = time.time()

    pk_2 = g_2 ** a

    end = time.time()
    time_1 = end - start
    sum_time += time_1 
    
times = sum_time/10    
print('Calculate an exponentiation on G2:', format(times * 1000, '7.2f'))  
with open('Results/Test.txt', 'a') as f:
    f.write('Calculate an exponentiation on G2:' + format(times * 1000, '7.2f')) 
    f.write('\n')
    
sum_time = 0
for i in range(10): 
    c = group.random(ZR)
   
    start = time.time()

    pk_3 = e_g1g2 ** c

    end = time.time()
    time_1 = end - start
    sum_time += time_1   
    
times = sum_time/10     
print('Calculate an exponentiation on GT:', format(times * 1000, '7.2f'))  
with open('Results/Test.txt', 'a') as f:
    f.write('Calculate an exponentiation on GT:' + format(times * 1000, '7.2f')) 
    f.write('\n')
    
sum_time = 0
for i in range(10): 
    start = time.time()

    kw = 'L'
    Hash = group.hash(kw, G1)

    end = time.time()
    time_1 = end - start    
    sum_time += time_1  
    
times = sum_time/10         
print('Calculate the hash of a string to G1:', format(times * 1000, '7.2f'))  
with open('Results/Test.txt', 'a') as f:
    f.write('Calculate the hash of a string to G1:' + format(times * 1000, '7.2f')) 
    f.write('\n')
    
sum_time = 0
for i in range(10): 
    start = time.time()

    kw = 'L'
    Hash = group.hash(kw, G2)

    end = time.time()
    time_1 = end - start
    sum_time += time_1     

times = sum_time/10     
print('Calculate the hash of a string to G2:', format(times * 1000, '7.2f'))  
with open('Results/Test.txt', 'a') as f:
    f.write('Calculate the hash of a string to G2:' + format(times * 1000, '7.2f')) 
    f.write('\n')

a = group.random(ZR)
b = group.random(ZR)
tk_1 = g_1 ** a
tk_2 = g_1 ** b
tk_3 = g_2 ** a
tk_4 = g_2 ** b

sum_time = 0
for i in range(10): 
    start = time.time()

    tk_12 = tk_1 * tk_2

    end = time.time()
    time_1 = end - start
    sum_time += time_1      

times = sum_time/10     
print('Calculate a multiplication on G1:', format(times * 10000, '7.2f'))  
with open('Results/Test.txt', 'a') as f:
    f.write('Calculate a multiplication on G1:' + format(times * 1000, '7.2f')) 
    f.write('\n')
    
sum_time = 0
for i in range(10): 
    start = time.time()

    tk_34 = tk_3 * tk_4

    end = time.time()
    time_1 = end - start
    sum_time += time_1  

times = sum_time/10          
print('Calculate a multiplication on G2:', format(times * 10000, '7.2f')) 
with open('Results/Test.txt', 'a') as f:
    f.write('Calculate a multiplication on G2:' + format(times * 1000, '7.2f')) 
    f.write('\n')
    
sum_time = 0
for i in range(10): 
    start = time.time()

    pair = e_g1g2 * e_g1g2

    end = time.time()
    time_1 = end - start
    sum_time += time_1     

times = sum_time/10      
print('Calculate a multiplication on GT:', format(times * 10000, '7.2f')) 
with open('Results/Test.txt', 'a') as f:
    f.write('Calculate a multiplication on GT:' + format(times * 1000, '7.2f')) 
    f.write('\n')
    
    
    #g1 = pairing_group.random(G1)
    #a, b = pairing_group.random(ZR), pairing_group.random(ZR)
    #g1_ab = g1 ** (a * b)
    
    #attr_1 = pairing_group.hash('1', ZR)
    #attr_2 = pairing_group.hash('2', ZR)
    #attr_3 = pairing_group.hash('3', ZR)
    #attr_4 = pairing_group.hash('4', ZR)
    #attr_5 = pairing_group.hash('5', ZR)
    #attr_list = [str(attr_1), str(attr_2), str(attr_3), str(attr_4), str(attr_5)]    
    #policy_str = str(attr_1) + ' and ' + str(attr_2) + ' and ' + str(attr_3) + ' and ' + str(attr_4) + ' and ' + str(attr_5)     
    
    #attr_1 = g1_ab * pairing_group.hash('1', G1)
    #attr_2 = g1_ab * pairing_group.hash('2', G1)
    #attr_3 = g1_ab * pairing_group.hash('3', G1)
    #attr_4 = g1_ab * pairing_group.hash('4', G1)
    #attr_5 = g1_ab * pairing_group.hash('5', G1)    
    
    #attr_1 = re.sub(r'[\[\], ]', '', str(attr_1))
    #attr_2 = re.sub(r'[\[\], ]', '', str(attr_2))
    #attr_3 = re.sub(r'[\[\], ]', '', str(attr_3))
    #attr_4 = re.sub(r'[\[\], ]', '', str(attr_4))
    #attr_5 = re.sub(r'[\[\], ]', '', str(attr_5))
       
    #attr_list = [attr_1, attr_2, attr_3, attr_4, attr_5]
    #policy_str = attr_1 + ' and ' + attr_2 + ' and ' + attr_3 + ' and ' + attr_4 + ' and ' + attr_5    
