from dataclasses import replace
import time
import timeit

flag = "ctf{its_dummy_flag}" # 19 chars
prime = 19

#for substitution of characters
def substitution(char):
    switch = {
        'a' : 'z',
        'b' : 'j',
        'c' : 's',
        'd' : 'q',
        'e' : 'r',
        'f' : 'y',
        'g' : 'i',
        'h' : 'w',
        'i' : 'm',
        'j' : 'h',
        'k' : 'f',
        'l' : 'g',
        'm' : 'b',
        'n' : 'c',
        'o' : 'x',
        'p' : 'e',
        'q' : 'a',
        'r' : 't',
        's' : 'u',
        't' : 'o',
        'u' : 'd',
        'v' : 'k',
        'w' : 'n',
        'x' : 'l',
        'y' : 'p',
        'z' : 'v',
        '{' : '=',
        '}' : '_',
        '=' : '}',
        '_' : '{'
        }
    return switch.get(char,char)

# compute hash of the supplied string
def compute_hash(password):
    password = password.ljust(prime,"=")[0:prime] # Adds = as a char to make it 19 bytes length
    #print(password)
    hash = ""
    for i in range(prime):
        #print(i, (7*i+4)%prime)
        hash += substitution(password[(7*i+4)%prime]) # 4, 11, 18, 6, 13,
        #print(substitution(password[(7*i+4)%prime]), (password[(7*i+4)%prime])) 
    return hash

# to check the correctness of the supplied password
def password_checker(password):
    hash = compute_hash(password)
    for i in range(len(flag)):
        time.sleep(1)
        if(flag_hash[i]!=hash[i]):
            print(flag_hash[i], hash[i])
            return False
    return True

def password_handler(password):
    if(password):
        # measure the time measured to check password correctness
        start = timeit.default_timer()
        if(password_checker(password)):
            print("Access Granted")
        end = timeit.default_timer()
        runtime = end-start
        #print("Time taken to verify = ", runtime)

import random
given_chars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '}', '=', '_' ]
random.shuffle(given_chars)

pwd_guess = ''
for i in range(prime):
    pwd_guess = pwd_guess + given_chars[i]
pwd_guess = "actf{its_dummy_flag}"

flag_hash = compute_hash(flag)

for i in range(prime):
    random.shuffle(given_chars)
    pos = (7*i+4)%prime
    print(pos)

    for j in range(len(given_chars)): ### cos starting with 0
        start = timeit.default_timer()
        password_handler(pwd_guess)
        end = timeit.default_timer()
        runtime = end-start

        if int(runtime) == i+1:
            pwd_guess = pwd_guess[:pos] + given_chars[j] + pwd_guess[pos+1:]
        else:
            break

    print("identified", pos, pwd_guess[pos], flag[pos])
    exit()

print("guessed pwd", pwd_guess)
