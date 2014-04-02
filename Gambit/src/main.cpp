#include <string.h>
#include <iostream>
#include "keccak.h"
#include "gambit.h"

/* DISCLAIMER
 * This is NOT a reference implementation!
 * This is a quick and dirty implementation. The software is not thoroughly
 * tested, and not at all tested on platforms other than Intel x86,
 * Windows OS, and CodeBlocks/GNU compiler. Once tested and verified, the
 * purpose of this program is to print test vectors to stdout that can
 * be compared to the output of another implementation.
 */

using namespace std;
using namespace keccak;
using namespace gambit;

void coutarray(uint8_t *buf, int len)
{
    for (int i=0; i < len; i++)
        cout << std::hex << (int)(buf[i]/16) << (int)(buf[i]%16) << std::dec;
}

void test256(salt &salt, const char *pwd, unsigned int pwd_len,
             const uint64_t* ROM, unsigned int ROM_len,
             unsigned int t, unsigned int m)
{
    seed256 sd;
    gambit256(salt, pwd, pwd_len, ROM, ROM_len, t, m, sd);
    cout << "  sd256: ";
    coutarray(sd, 32);
    cout << endl;
}

void test512(salt &salt, const char *pwd, unsigned int pwd_len,
             const uint64_t* ROM, unsigned int ROM_len,
             unsigned int t, unsigned int m)
{
    seed512 sd;
    gambit512(salt, pwd, pwd_len, ROM, ROM_len, t, m, sd);
    cout << "  sd512: ";
    coutarray(sd, 32);
    cout << endl << "         ";
    coutarray(sd+32, 32);
    cout << endl;
}

int main()
{
    cout << "state size: " << sizeof(keccak_state) << endl;

    keccak_state A;
    cout << std::hex;
    cout << "state after init: " << A.word_read(0) << ","
                                 << A.word_read(1) << ", ..." << endl;
    A.f();
    cout << "state after f(): " << A.word_read(0) << ","
                                << A.word_read(1) << ", ..." << endl;

    salt salt;
    char pwd[151];
    unsigned int pwd_len = 0;
    unsigned int t = 128;
    unsigned int m = 511;
    uint64_t ROM[128] = {0};
    unsigned int ROM_len = 1;

    cout << endl << "SALT" << endl;
    for (int i = 1; i <= 128; i*=2)
    {
        memset(salt, 0, sizeof(salt));
        salt[15 - ((i-1) / 8)] = (1 << ((i-1) % 8));
        cout << "salt: ";
        coutarray(salt, 16);
        cout << endl;
        test256(salt, pwd, pwd_len, ROM, ROM_len, t, m);
        test512(salt, pwd, pwd_len, ROM, ROM_len, t, m);
    }
    memset(salt, 0, sizeof(salt));

    cout << endl << "PASSWORD" << endl;
    for (int i = 2; i > -3; i--)
    {
        memset(pwd, 0x00, 152);
        cout << "pwd: " << std::dec << (i+152)%152 << " * 0x00" << endl;
        test256(salt, pwd, (i+152)%152, ROM, ROM_len, t, m);
        cout << "pwd: " << std::dec << (i+120)%120 << " * 0x00" << endl;
        test512(salt, pwd, (i+120)%120, ROM, ROM_len, t, m);
        if (i != 0)
        {
            memset(pwd, 0x01, 152);
            cout << "pwd: " << std::dec << (i+152)%152 << " * 0x01" << endl;
            test256(salt, pwd, (i+152)%152, ROM, ROM_len, t, m);
            cout << "pwd: " << std::dec << (i+120)%120 << " * 0x01" << endl;
            test512(salt, pwd, (i+120)%120, ROM, ROM_len, t, m);

            memset(pwd, 0x4A, 152);
            cout << "pwd: " << std::dec << (i+152)%152 << " * 0x4A" << endl;
            test256(salt, pwd, (i+152)%152, ROM, ROM_len, t, m);
            cout << "pwd: " << std::dec << (i+120)%120 << " * 0x4A" << endl;
            test512(salt, pwd, (i+120)%120, ROM, ROM_len, t, m);

            memset(pwd, 0xFF, 152);
            cout << "pwd: " << std::dec << (i+152)%152 << " * 0xFF" << endl;
            test256(salt, pwd, (i+152)%152, ROM, ROM_len, t, m);
            cout << "pwd: " << std::dec << (i+120)%120 << " * 0xFF" << endl;
            test512(salt, pwd, (i+120)%120, ROM, ROM_len, t, m);
        }
    }

    cout << endl << "T/M" << endl;
    for (t = 1; t < 40000; t = t*9/4)
    {
        for (m = (t * 21 / 2 - 1) | 1; m > 0; m = (m==1)? 0 : (m / 3) | 1)
        {
            cout << std::dec << "t: " << t << " m: " << m << endl;
            test256(salt, pwd, pwd_len, ROM, ROM_len, t, m);
        }
        for (m = (t * 17 / 2 - 1) | 1; m > 0; m = (m==1)? 0 : (m / 3) | 1)
        {
            cout << std::dec << "t: " << t << " m: " << m << endl;
            test512(salt, pwd, pwd_len, ROM, ROM_len, t, m);
        }
    }

    cout << endl << "DERIVATION" << endl;
    pwd_len = 0;
    t = 16;
    m = 25;

    {
        seed256 sd;
        dkid256 dkid;
        uint8_t key[16];

        gambit256(salt, pwd, pwd_len, ROM, ROM_len, t, m, sd);
        for (int i = 1; i <= 1024; i*=2)
        {
            memset(dkid, 0, sizeof(dkid));
            dkid[((i-1) / 8)] = (1 << ((i-1) % 8));
            gambit256(sd, dkid, key, 16);
            cout << "256 dkid: bit" << i-1 << " set" << endl << "  key: ";
            coutarray(key, 16);
            cout << endl;
        }
    }

    {
        seed512 sd;
        dkid512 dkid;
        uint8_t key[16];

        gambit512(salt, pwd, pwd_len, ROM, ROM_len, t, m, sd);
        for (int i = 1; i <= 1024; i*=2)
        {
            memset(dkid, 0, sizeof(dkid));
            dkid[((i-1) / 8)] = (1 << ((i-1) % 8));
            gambit512(sd, dkid, key, 16);
            cout << "512 dkid: bit" << i-1 << " set" << endl << "  key: ";
            coutarray(key, 16);
            cout << endl;
        }
    }

    return 0;
}
