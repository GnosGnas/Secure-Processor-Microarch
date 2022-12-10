import os
from time import time

open('GE_values.txt', 'w').close()
for i in range(100):
	t1 = time()
	os.system("make clean")
	os.system("make")
	os.system("taskset --cpu-list 2 ./attack >> GE_values.txt")
	t2 = time()
	print(f"{i} : {t2-t1}")
