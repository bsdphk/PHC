#include "keccak.h"
#include "gambit.h"
#include <cassert>
#include <cstring>

#define KECCAK_BACKWARD_RATIO 100
// todo: 100 is not an actual value. actual value has to be found.

int PHS(void *out, size_t outlen, const void *in, size_t inlen,
        const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
    assert (saltlen = 16);

    uint64_t ROM[1] = {0};

    gambit::dkid256 dkid;
    std::memset(dkid, 0, sizeof(dkid));

    gambit::gambit256(*(gambit::salt*)salt, (const char*)in, (unsigned int)inlen, ROM, 1, t_cost, m_cost,
                      dkid, out, (unsigned int)outlen);

    return 0;
}

namespace gambit
{
    using namespace keccak;

    unsigned int gcd(unsigned int a, unsigned int b)
    {
        while (true)
        {
            a %= b;
            if (a == 0) return b;
            b %= a;
            if (b == 0) return a;
        }
    }

    void gambit(unsigned int r,
                const void *salt,
                const char* pwd, unsigned int pwd_len,
                const uint64_t* ROM, unsigned int ROM_len,
                unsigned int cost_t, unsigned int cost_m,
                void *seed)
    {
        assert (cost_m & 1);
        assert (cost_t > 0);
        assert (cost_m*2 <= cost_t * (r/8) );
        assert (pwd_len+16+1 <= r);

        uint64_t* mem = new uint64_t[cost_m];
        memset(mem, 0, sizeof(uint64_t)*cost_m);

        unsigned int f;
        if (cost_m == 1)
            f = 1;
        else
        {
            f = cost_m * KECCAK_BACKWARD_RATIO / (KECCAK_BACKWARD_RATIO + 1);
            while ( (gcd(cost_m, f) != 1) || (gcd(cost_m, f - 1) != 1) ) f--;
        }

        keccak_state A;
        A.block_absorb(salt, 0, 16);
        A.block_absorb(pwd, 16, pwd_len);
        A.pad101_xor(16 + pwd_len, r-1);
        A.f();

        unsigned int wrtp = 0;
        unsigned int rdp = 0;
        unsigned int romp = 0;

        for (; cost_t > 0; cost_t--)
        {
            for (int i = 0; i < 18; i++)
            {
                mem[wrtp] ^= A.word_read(i);
                wrtp++;
                if (wrtp == cost_m) wrtp = 0;

                A.word_write_xor(i, mem[rdp] ^ ROM[romp]);
                rdp += f;
                if (rdp >= cost_m) rdp -= cost_m;
                romp ++;
                if (romp >= ROM_len) romp = 0;
            }
            A.f();
        }

        memset(mem, 0, sizeof(uint8_t)*cost_m);
        delete [] mem;

        A.block_squeeze(seed, r, (200-r));
    }

    // // // // // // // // 256 // // // // // // // //

    void gambit256(const salt salt,
                   const char* pwd, unsigned int pwd_len,
                   const uint64_t* ROM, unsigned int ROM_len,
                   unsigned int cost_t, unsigned int cost_m,
                   seed256 seed)
    {
        gambit(168, salt, pwd, pwd_len, ROM, ROM_len, cost_t, cost_m, seed);
    }

    void gambit256(const seed256 &seed,
                   dkid256 dkid, void *key, int key_len)
    {
        assert (key_len <= 168);

        keccak_state A;
        A.block_absorb(dkid, 0, 168);
        A.block_absorb(seed, 168, 32);
        A.f();
        A.block_squeeze(key, 0, key_len);
    }

    void gambit256(const salt &salt,
                   const char* pwd, unsigned int pwd_len,
                   const uint64_t* ROM, unsigned int ROM_len,
                   unsigned int cost_t, unsigned int cost_m,
                   dkid256 dkid, void *key, int key_len)
    {
        seed256 seed;
        gambit256(salt, pwd, pwd_len, ROM, ROM_len, cost_t, cost_m, seed);
        gambit256(seed, dkid, key, key_len);
        memset(seed, 0, 32);
    }

    // // // // // // // // 512 // // // // // // // //

    void gambit512(const salt salt,
                   const char* pwd, unsigned int pwd_len,
                   const uint64_t* ROM, unsigned int ROM_len,
                   unsigned int cost_t, unsigned int cost_m,
                   seed512 seed)
    {
        gambit(136, salt, pwd, pwd_len, ROM, ROM_len, cost_t, cost_m, seed);
    }

    void gambit512(const seed512 &seed,
                   dkid512 dkid, void *key, int key_len)
    {
        assert (key_len <= 136);

        keccak_state A;
        A.block_absorb(dkid, 0, 136);
        A.block_absorb(seed, 136, 64);
        A.f();
        A.block_squeeze(key, 0, key_len);
    }

    void gambit512(const salt &salt,
                   const char* pwd, unsigned int pwd_len,
                   const uint64_t* ROM, unsigned int ROM_len,
                   unsigned int cost_t, unsigned int cost_m,
                   dkid512 dkid, void *key, int key_len)
    {
        seed512 seed;
        gambit512(salt, pwd, pwd_len, ROM, ROM_len, cost_t, cost_m, seed);
        gambit512(seed, dkid, key, key_len);
        memset(seed, 0, 64);
    }
}
