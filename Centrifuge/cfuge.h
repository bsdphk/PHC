/*
	Centrifuge, a password hashing algorithm
	2014 (c) Rafael Alvarez
*/
#ifndef CENTRIFUGE
#define CENTRIFUGE

// types


// prototype
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);

int cfuge(const uint8_t *password, uint32_t passlen, const uint8_t *salt, uint32_t saltlen, uint8_t *out, uint32_t outlen, const uint64_t p_mem, const uint64_t p_time);

#endif