#ifndef CATFISH_H
#define CATFISH_H

int catfish(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen, const uint8_t *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);

#define PHS(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost) \
    catfish((uint8_t *)(out), (outlen), (uint8_t *)(in), (inlen), (uint8_t *)(salt), (saltlen), (t_cost), (m_cost))

#endif  // CATFISH_H
