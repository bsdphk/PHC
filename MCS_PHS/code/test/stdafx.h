//# Algorithm Name: Test
//# Principal Submitter: Mikhail Maslennikov
//# Revision: 12.02.2014 

#pragma once


#include <stdio.h>
#include <tchar.h>
#include <time.h>
#include <memory.h>
#include <string.h>
#include <windows.h>
#include <string>
#include <iostream>
using namespace std;


#include "../mcssha8/mcssha8.h"
#include "../mcs_psw/mcs_psw.h"

void PrintCommandInfo();
bool IsParamPresentStd(string Param,string FindString);
string GetOneParamStd(string sParam,string sFindString);


static unsigned char text[] = {0xC1, 0xEC, 0xFD, 0xFC};
static unsigned char control_hash[] = 
									  {
                                        0x02, 0x56, 0x32, 0x5f, 0x6b, 0xb8, 0xb0, 0xf0, 
										0x15, 0xff, 0x02, 0x86, 0x30, 0x18, 0x92, 0xb7, 
										0xa4, 0xe7, 0x7c, 0x58, 0x06, 0x28, 0x9d, 0x8f, 
										0x22, 0x7e, 0x7b, 0x9f, 0x0f, 0x63, 0xcf, 0x31, 
										0xfe, 0xc7, 0x19, 0x44, 0xdc, 0xeb, 0xd8, 0x99, 
										0xf4, 0x15, 0x0d, 0x74, 0xb4, 0x79, 0xe2, 0xd7, 
										0xbe, 0x6e, 0xff, 0x68, 0xbf, 0xaf, 0x74, 0x9d, 
										0x96, 0x63, 0xf8, 0x7c, 0xd4, 0x1c, 0x1d, 0x54
									  };

#define OUT_LEN     "-len"
#define SALT        "-salt"
#define TCOST       "-tcost"
#define MCOST       "-mcost"
#define PSW_LEN     "-pswlen"
#define TEST_NUM    "-testnum"

#define DEFAULT_PSW_LEN   5
#define DEFAULT_TEST_NUM  100
#define DEFAULT_SALT_LEN  16
#define DEFAULT_OUT_LEN   32
