//# Algorithm Name: Test
//# Principal Submitter: Mikhail Maslennikov
//# Revision: 12.02.2014 

#include "stdafx.h"

// Test program for MCSSHA8 and MCS_PSW
int _tmain(int argc, _TCHAR* argv[])
{
	BYTE *out = NULL, *salt = NULL;
	size_t outlen = 0,inlen = 0, saltlen = 0, pswlen = 0;
	unsigned int t_cost = 0,m_cost = 0;
	DWORD dwErr = 0;
	string sParam;
	int i = 0,j = 0;
	string sTmp;
	int TestNum = 0;
    clock_t start = 0, finish = 0;
    float TstTime = 0;
    time_t t;
	BYTE rnd[32] = {0};
	BYTE Psw[128] = {0};


	do
	{
// Parameters uncorrect.	
		if(argc < 2)
		{
			PrintCommandInfo();
			return -1;
		}
// For parameter "hash" we test MCSSHA7 hash algorithm 
		if(argc == 2 && _stricmp((const char *)argv[1],"hash") == 0)
		{
			unsigned char hash[64];
			printf("\n######################    test MCSSHA8    ######################\n");
			Hash(512,text,32,hash);
			if(memcmp(hash,control_hash,64) == 0)
				printf("\n######################       SUCCESS      ######################\n");
			else 
				printf("\n######################        ERROR       ######################\n");
		}
	
// For parameter "speed" we test MCS_PSW speed 
		else if(argc >= 2 && _stricmp((const char *)argv[1],"speed") == 0)
		{
			printf("\n######################    test MCS_PSW speed    ######################\n");

			pswlen = DEFAULT_PSW_LEN;
			TestNum = DEFAULT_TEST_NUM;
			saltlen = DEFAULT_SALT_LEN;
            outlen = DEFAULT_OUT_LEN;
			if(argc > 2)sParam = (const char *)argv[2];

			sTmp = GetOneParamStd(sParam,PSW_LEN);
			if(sTmp != "")sscanf(sTmp.c_str(), "%d", &pswlen);

			sTmp = GetOneParamStd(sParam,TEST_NUM);
			if(sTmp != "")sscanf(sTmp.c_str(), "%d", &TestNum);

			sTmp = GetOneParamStd(sParam,TCOST);
			if(sTmp != "")sscanf(sTmp.c_str(), "%d", &t_cost);

			sTmp = GetOneParamStd(sParam,MCOST);
			if(sTmp != "")sscanf(sTmp.c_str(), "%d", &m_cost);

			if(m_cost == 0)m_cost = 256;

			printf("\n##########    password length = %d, c = %d, Cost = %d, test numbers = %d    ##########\n",pswlen, t_cost, m_cost, TestNum);

			if(pswlen > 64) 
			{
				dwErr = NTE_BAD_DATA;
				break;
			}
			salt = (BYTE *)malloc(saltlen);
			out = (BYTE *)malloc(outlen);

// Set random generator initial point
            time(&t);
			Hash(256,(BitSequence *)&t,sizeof(t)<<3,rnd);

			start = clock();
			for(i = 0; i < TestNum; i++)
			{
				Hash(256,rnd,256,rnd);
				memcpy(salt,rnd,saltlen);
				Hash(512,rnd,256,Psw);
			    if(PHS((void *)out,outlen,(const void *)Psw,pswlen,(const void *)salt,saltlen,t_cost,m_cost) == -1)break;
			}
            finish = clock();
            if(i != TestNum)
			{
				printf("\n######################    ERROR during test    ######################\n");
				break;
			}
            TstTime = (float)(finish - start)/CLOCKS_PER_SEC;
            printf("\n######################     Time = %f sec.     ######################\n\n",TstTime);

		}

// In all other cases we generate MCS_PSW sequence 
		else
		{
			inlen = strlen((const char *)argv[1]);
			printf("\n######################    test MCS_PSW    ######################\n");
			printf("\n######################    Hash for password %s    ######################\n",(const char *)argv[1]);
			if(argc > 2)sParam = (const char *)argv[2];
		
			sTmp = GetOneParamStd(sParam,OUT_LEN);
			if(sTmp != "")sscanf(sTmp.c_str(), "%d", &outlen);

			sTmp = GetOneParamStd(sParam,TCOST);
			if(sTmp != "")sscanf(sTmp.c_str(), "%d", &t_cost);

			sTmp = GetOneParamStd(sParam,MCOST);
			if(sTmp != "")sscanf(sTmp.c_str(), "%d", &m_cost);

			if(m_cost == 0)m_cost = 256;

			sTmp = GetOneParamStd(sParam,SALT);
			if(sTmp != "")
			{
				if(sTmp.length() %2 != 0)
				{
					printf("\n######################    ERROR: Uncorrect salt    ######################\n");
					return -1;
				}
				saltlen = sTmp.length()>>1;
				salt = (BYTE *)malloc(saltlen + 1);
				memset(salt,0,saltlen + 1);
				for(i = 0; i < sTmp.length(); i += 2)
				{
					j = 0;
					sscanf(sTmp.c_str() + i,"%02X",&j);
					salt[i>>1] = (BYTE)j;
				}

			}
			printf("\n######################    Salt %s, c = %d, Cost = %d   ######################\n",(const char *)sTmp.c_str(),t_cost,m_cost);


			out = (BYTE *)malloc(outlen);



			start = clock();
			if(PHS((void *)out,outlen,(const void *)argv[1],inlen,(const void *)salt,saltlen,t_cost,m_cost) == -1)
			{
				dwErr = GetLastError();
				printf("\n######################    ERROR 0x%X    ######################\n",dwErr);
				break;
			}
			else
			{
                finish = clock();
				char *buff = (char *)malloc((outlen<<1) + 1);
				memset(buff,0,(outlen<<1) + 1);
				for(int i = 0; i < outlen; i++)sprintf(buff + strlen(buff),"%02X",((BYTE *)out)[i]);
				printf("\n######################    %s    ######################\n",buff);
				TstTime = (float)(finish - start)/CLOCKS_PER_SEC;
				printf("\n######################     Time = %f sec.     ######################\n\n",TstTime);
				break;
			}

		
		}
	}while(0);

	if(out != NULL)free(out);
	if(salt != NULL)free(salt);

	return 0;
}



void PrintCommandInfo()
{
    cout << "Usage: " << "test.exe" << " hash\n";
    cout << "       for check hash or\n\n\n"; 
    cout << "       " << "test.exe" << " <Password> [Param1,Param2,...]\n";
    cout << "       where Params are:\n"; 
    cout << "                 -len<OutLen>               - output sequence length\n"; 
    cout << "                 -salt<Salt>                - salt sequence in hex (for example -salt0011223344556677889900aabbccddeeff)\n"; 
    cout << "                 -tcost<t_cost>             - value of t_cost parameter\n"; 
    cout << "                 -mcost<m_cost>             - value of m_cost parameter\n"; 
    cout << "       for get <Password> hash or\n\n\n"; 
    cout << "       " << "test.exe" << " speed [Param1,Param2,...]\n";
    cout << "       where Params are:\n"; 
    cout << "                 -pswlen<PswLen>            - random password length\n"; 
    cout << "                 -testnum<TestsNumber>      - the number of random tests\n"; 

}

//-----------------------------------------------------------------------------------
bool IsParamPresentStd(string Param,string FindString)
{
     int i = (int)Param.find(FindString);
     return(i != -1);
}
string GetOneParamStd(string sParam,string sFindString)
{
     string sValue = "";
     int i,j,len = (int)sParam.length(),len1 = (int)sFindString.length();
     i = (int)sParam.find(sFindString);
     if(i != -1)
     {
          sValue = sParam.substr(i + len1,len - i - len1);
           j = (int)sValue.find(',');
           if(j != -1)sValue.resize(j);
     }
     return sValue;
}
