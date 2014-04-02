// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

#ifndef SHA512_H
#define SHA512_H

#include "common.h"

class Sha512
{
public:
	Sha512()  {}
	~Sha512() {}

	static const unsigned int HASH_LENGTH = 64;

	static void hash(const void *message, size_t length, void *out, uint32_t outLength = 64);
	void        init();
	void        update(const void *message, size_t length);
	void        finish(void *out, uint32_t outLength = 64);

private:
	uint64_t m_messageLengthHi;
	uint64_t m_messageLengthLo;
	uint64_t m_state[8];
	uint64_t m_block[16];
};

#endif
