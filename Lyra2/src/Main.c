/*
   LYRA2 reference source code package - <http://www.lyra-kdf.net/>

   Written in 2014 by Leonardo de Campos Almeida <lalmeida@larc.usp.br>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include "Lyra2.h"
#include "Sponge.h"

/**
 * Generates the test vectors for Lyra2.
 *
 * @param t Parameter to determine the processing time (T)
 * @param r  Memory cost parameter (defines the number of rows of the memory matrix, R)
 */
int testVectors(unsigned int  t, unsigned int  r) {
    //=================== Basic variables, with default values =======================//
    int kLen = 64;
    unsigned char *pwd;
    int pwdLen = 11;
    unsigned char *salt;
    int saltLen = 16;
	
	srand(time(NULL));
	int i;
    int countSample;
    int indexSalt = 0;
    //==========================================================================/

    unsigned char *K = malloc(kLen);

    /* Generating vectors with the input size varying from 0 to 128 bytes,
     * and values varying from 0 to 127. The salt size is fixed in 16 bytes, 
	 * and its value varies from 0 to 256.
	 */
    for (countSample = 0; countSample <= 128; countSample++) {
        pwdLen = countSample;
        int count;
        pwd = malloc(sizeof (pwd) * pwdLen);
        for (count = 0; count < pwdLen; count++) {
            pwd[count] = count;
        }

        salt = malloc(sizeof (salt) * saltLen);
        for (count = 0; count < saltLen; count++) {
            salt[count] = saltLen * indexSalt + count;
        }
        indexSalt++;
        if (indexSalt == saltLen)
            indexSalt = 0;

        PHS(K, kLen, pwd, pwdLen, salt, saltLen, t, r);

        printf("\ninlen: %d\n", pwdLen);
        printf("t_cost: %d\n", t);
        printf("m_cost: %d\n", r);
        printf("outlen: %d\n", kLen);

        printf("In: ");
        for (i = 0; i < pwdLen; i++) {
            printf("%02x ", pwd[i]);
        }
        printf("\n");

        printf("Salt: ");
        for (i = 0; i < saltLen; i++) {
            printf("%02x ", salt[i]);
        }
        printf("\n");

        printf("Out: ");
        for (i = 0; i < kLen; i++) {
            printf("%02x ", K[i]);
        }
        printf("\n");
    }
    
	/* Generating vectors with the input size varying from 0 to 128 bytes,
     * and values varying from 128 to 255. The salt size is fixed in 16 bytes, 
	 * and its value varies from 0 to 256.
	 */
    for (countSample = 128; countSample <= 256; countSample++) {
        pwdLen = countSample - 127;
        int count;
        pwd = malloc(sizeof (pwd) * pwdLen);
        for (count = 0; count < pwdLen; count++) {
            pwd[count] = count + 128;
        }

        salt = malloc(sizeof (salt) * saltLen);
        for (count = 0; count < saltLen; count++) {
            salt[count] = saltLen * indexSalt + count;
        }
        indexSalt++;
        if (indexSalt == saltLen)
            indexSalt = 0;

        PHS(K, kLen, pwd, pwdLen, salt, saltLen, t, r);

        printf("\ninlen: %d\n", pwdLen);
        printf("t_cost: %d\n", t);
        printf("m_cost: %d\n", r);
        printf("outlen: %d\n", kLen);

        printf("In: ");
        for (i = 0; i < pwdLen; i++) {
            printf("%02x ", pwd[i]);
        }
        printf("\n");

        printf("Salt: ");
        for (i = 0; i < saltLen; i++) {
            printf("%02x ", salt[i]);
        }
        printf("\n");

        printf("Out: ");
        for (i = 0; i < kLen; i++) {
            printf("%02x ", K[i]);
        }
        printf("\n");
    }
    return 0;
}

int main(int argc, char *argv[]) {
    //=================== Basic variables, with default values =======================//
    int kLen = 64;
    int t = 0;
    int r = 0;
    char *pwd = "Lyra sponge";
    int pwdLen = 11;
    char *salt = "saltsaltsaltsalt";
    int saltLen = 16;
    //==========================================================================/
    
    switch (argc) {
        case 2:
            if (strcmp(argv[1], "--help") == 0) {
                printf("Usage: \n");
                printf("       Lyra2 pwd salt kLen tCost nRows \n\n");
                printf("Inputs:\n");
                printf(" - pwd: the password\n");
                printf(" - salt: the salt\n");
                printf(" - kLen: output size\n");
                printf(" - tCost: the time cost parameter\n");
                printf(" - nRows: the number of rows parameter\n");
                printf("\n");
                printf("Or:\n");
                printf("       Lyra2 tCost nRows --testVectors (to generate test vectors and test Lyra2 operation)\n\n");
                return 0;
            } else {
                printf("Invalid options.\nFor more information, try \"Lyra2 --help\".\n");
                return 0;
            }
            break;
        case 6:
            pwd = argv[1];
            pwdLen = strlen(pwd);
            salt = argv[2];
            saltLen = strlen(salt);
            kLen = atoi(argv[3]);
            t = atoi(argv[4]);
            r = atoi(argv[5]);
            break;
        case 4:
            if (strcmp(argv[3], "--testVectors") == 0) {
                t = atoi(argv[1]);
                r = atoi(argv[2]);
                testVectors(t, r);
                return 0;
            } else {
                printf("Invalid options.\nFor more information, try \"Lyra2 --help\".\n");
                return 0;
            }
            break;
        default:
            printf("Invalid options.\nTry \"Lyra2 --help\" for help.\n");
            return 0;
    }
    
    unsigned char *K = malloc(kLen);

    printf("Inputs: \n");
    printf("\tPassword: %s\n", pwd);
    printf("\tPassword Size: %d\n", pwdLen);
    printf("\tSalt: %s\n", salt);
    printf("\tOutput Size: %d\n", kLen);
    printf("------------------------------------------------------------------------------------------------------------------------------------------\n");

    printf("Parameters: \n");
    printf("\tT: %d\n", t);
    printf("\tR: %d\n", r);
    printf("\tC: %d\n", N_COLS);
    printf("\tMemory: %ld bits\n", ((long) (N_COLS * r * BLOCK_LEN_BYTES)));
    printf("------------------------------------------------------------------------------------------------------------------------------------------\n");

    PHS(K, kLen, pwd, pwdLen, salt, saltLen, t, r);

    printf("Output: \n");

    printf("\n\tK: ");
    int i;
    for (i = 0; i < kLen; i++) {
        printf("%x|", K[i]);
    }
    printf("\n");
    printf("------------------------------------------------------------------------------------------------------------------------------------------\n");
    return 0;
}

