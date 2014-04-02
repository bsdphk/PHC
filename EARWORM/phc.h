#ifndef EARWORM_PHC_H
#define EARWORM_PHC_H

int PHS_initialize_arena(unsigned int m_cost);

int PHS(void *out, size_t outlen, 
        const void *in, size_t inlen,
        const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost);

#endif
