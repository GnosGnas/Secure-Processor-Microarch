attack:
	@echo "To perform timing attack, use make timing"
	@echo "To perform evict+time attack, use make evict"
	@echo "To perform evict+time attack for round 2, use make evict2"

timing: timing.c common.o
	gcc -I. -Ilib/ -O3 timing.c -o timing lib/aes_1024.o common.o -lm
	@echo "Execute the command now: taskset --cpu-list <cpu number> ./timing"
#	gcc -I. -O3 attack.c -o attack lib/aes_2048.o common.o -lm
#	gcc -I. -O3 attack.c -o attack lib/aes8_1024.o common.o -lm

evict: evict.c common.o
	gcc -I. -Ilib/ -O3 evict.c -o evict lib/aes_1024.o common.o -lm
	@echo "Execute the command now: taskset --cpu-list <cpu number> ./evict"
#	gcc -I. -O3 attack.c -o attack lib/aes_2048.o common.o -lm
#	gcc -I. -O3 attack.c -o attack lib/aes8_1024.o common.o -lm

evict2: evict_rnd2.c common.o
	gcc -I. -Ilib/ -O3 evict_rnd2.c -o evict lib/aes_1024.o common.o -lm
	@echo "Execute the command now: taskset --cpu-list <cpu number> ./evict"
#	gcc -I. -O3 attack.c -o attack lib/aes_2048.o common.o -lm
#	gcc -I. -O3 attack.c -o attack lib/aes8_1024.o common.o -lm

common.o: common.c
	gcc -O3 common.c  -c -o common.o

clean:
	rm -f timing correlate *.o evict
