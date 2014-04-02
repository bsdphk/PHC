
/*
  Implementation of the 'Rig' Password Hashing Scheme
	
   March 31, 2014

  Author: Arpan Jati (arpanj@iiitd.ac.in)
 */

#include <stdio.h>
#include <conio.h>
#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "rig.h"

int Min(int A, int B)
{
	if(A>B)
		return B;
	else return A;
}

void ShowUsage()
{
	printf("\n Usage \n ");
	printf("\n rig [password] [salt] [m_cost] [t_cost] \n ");

	exit(1);
}

void PrintHash( const char* String,  unsigned char* Hash)
{
	int k;
	printf("\n %s \n " , String);
	for(k=0;k<64;k++)
	{
		printf("%02X", Hash[k]);
		if(((k+1)%8)==0) printf(" ");
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	int i=0, j=0, k=0, l=0;

	if(argc != 5)
	{
		 ShowUsage();
	}

	char* pass = argv[1];
	char* salt =  argv[2];
	
	int m_cost = atoi(argv[3]);
	int t_cost = atoi(argv[4]);
	
	double MS_EL = 0;
	
	unsigned char Hash[64];

	printf("\n Password : %s", pass );
	printf("\n salt : %s", salt );
	printf("\n m_cost : %d", m_cost );
	printf("\n t_cost : %d", t_cost );

	PHS(Hash, 64, (unsigned char *)pass, strlen(pass), (unsigned char*)salt, strlen(salt), t_cost, m_cost);

	PrintHash("\n\n Hash : ", Hash);
	 		
	//getchar();

	return 0;
}
