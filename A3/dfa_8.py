# SPM (CS6330) Assignment 3
# Authors: Sai Dheeraj Ettamsetty (CS18B055) and Surya Prasad S (EE19B121)
import os
from aes import *
from time import time

# Variables for the code
PATH = './'	# Location of given file
NUM_FAULTS_RND9 = 4		# Number of faults used for Round 9 Analysis (Should be 4 as we don't have the correct plaintext)
NUM_FAULTS_RND8 = 1		# Number of Faults used for Round 8 Analysis (Should be less than or equal to 4)

Time_start = time()

fp = open(PATH + 'CS18B055_EE19B121.txt', 'r')
texts = []
for line in fp:
    texts.append(line.split())
fp.close()
# print(texts)

def str_to_lst(hex_str):
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def get_me_my_keys(cf, fcf):
    f8 = fcf
    f8 = [f8[i:i+2] for i in range(0, len(f8), 2)]
    ref = cf
    ref = [ref[i:i+2] for i in range(0, len(ref), 2)]
    
    r9faults = []
    for i in range(NUM_FAULTS_RND9):
    	if i==0:
    		r9faults.append(ref[0:0] + f8[0:1] + ref[1:7] + f8[7:8] + ref[8:10] + f8[10:11] + ref[11:13] + f8[13:14] + ref[14:16])
    	if i==1:
    		r9faults.append(ref[0:1] + f8[1:2] + ref[2:4] + f8[4:5] + ref[5:11] + f8[11:12] + ref[12:14] + f8[14:15] + ref[15:16])
    	if i==2:
    		r9faults.append(ref[0:2] + f8[2:3] + ref[3:5] + f8[5:6] + ref[6:8] + f8[8:9] + ref[9:15] + f8[15:16] + ref[16:16])
    	if i==3:
    		r9faults.append(ref[0:3] + f8[3:4] + ref[4:6] + f8[6:7] + ref[7:9] + f8[9:10] + ref[10:12] + f8[12:13] + ref[13:16])
    		
    s = [''.join(i) for i in r9faults]
    for i in range(NUM_FAULTS_RND9):
        f = open("mydata.txt", "a")
        f.write(f"{''.join(ref)}, {s[i]}\n")
        f.close()

# Function to find all round keys given key10
def reverse_key(key10):
	subkeys = [0] * 176

	for i in range(160,176):
		subkeys[i] = key10[i - 160]

	for i in range(156,-1,-4):
		if i % 16 == 0 :
			subkeys[i] = subkeys[i + 16] ^ sbox[subkeys[i + 13]] ^ rcon[i>>4]
			subkeys[i + 1] = subkeys[i + 17] ^ sbox[subkeys[i + 14]]
			subkeys[i + 2] = subkeys[i + 18] ^ sbox[subkeys[i + 15]]
			subkeys[i + 3] = subkeys[i + 19] ^ sbox[subkeys[i + 12]]
		else:
			subkeys[i] = subkeys[i + 16] ^ subkeys[i + 12]
			subkeys[i + 1] = subkeys[i + 17] ^ subkeys[i + 13]
			subkeys[i + 2] = subkeys[i + 18] ^ subkeys[i + 14]
			subkeys[i + 3] = subkeys[i + 19] ^ subkeys[i + 15]

	return subkeys

open("mydata.txt", "w").close() ### This is very important to clear all contents of the file before we write something in it.
f = open("mydata.txt", "a")
f.write("75a9c13e29bda0904181de983a2117bf, f58f293450bc8120d99860623f1b6aae") # Some garbage PT and CT - Exhaustive search is performed if intersection is NULL set
f.write("\n")
f.close()
for i in range(1, NUM_FAULTS_RND8+1):
    get_me_my_keys(texts[i][0], texts[i][1])

os.system("""python3 dfa_9vi.py -round 9 -input mydata.txt | grep "10th round Key" > finalout.txt""")
#os.remove("mydata.txt")

fp = open('finalout.txt', 'r')
last_rk = ""
for line in fp:
    print(line)
    last_rk = line
fp.close()
#os.remove('finalout.txt')

Time_rndkey10 = time() - Time_start

print(last_rk)
last_rk = last_rk.split('y')[-1]
last_rk = last_rk.strip()
last_rk = last_rk.split(',')
print(last_rk)
last_rk = [int(i.strip('[]').strip()) for i in last_rk]
# print(last_rk)
all_keys = reverse_key(last_rk)
Time_end = time() - Time_start

Rk = open('roundkeys.txt', 'w')

for i in range(0, len(all_keys), 16):
    if i == 0:
        print(f"Full Secret key: {all_keys[i:i+16]}")
    else:
        print(f"Round {i//16} key: {all_keys[i:i+16]}")
        Rk.write(f"round {i//16} : {all_keys[i:i+16]}\n")

Rk.close()

print("\nTime taken to compute 10th round key", Time_rndkey10)
print("Time taken for whole process", Time_end)

