// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

#ifndef BLOWFISH_H
#define BLOWFISH_H

#include "common.h"

class Blowfish
{
public:
	Blowfish();
	~Blowfish();

	void initKey448(const void *key448);
	void cbcEncrypt(const void *in, const void *out, uint32_t blocks);

private:
	uint32_t m_l;
	uint32_t m_r;
	uint32_t m_p[16 + 2];
	uint32_t m_sboxes[4 * 256];
};

#endif
