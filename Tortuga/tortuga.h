#ifndef TORTUGA_H
#define TORTUGA_H

#define TORTUGA_SALT_BYTES    16
#define TORTUGA_MIN_KEY_BYTES 16

unsigned int tortuga_internal_key_size(const unsigned int m_cost);

void tortuga(unsigned char * out  , const unsigned int   out_size,
       const unsigned char * input, const unsigned int input_size,
       const unsigned char * salt , const unsigned int  salt_size,
 const unsigned int t_cost, const unsigned int m_cost);

#endif
