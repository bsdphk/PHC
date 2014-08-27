// Copyright (c) 2014 Steve Thomas <steve AT tobtu DOT com>

#ifndef BATTCRYPT_H
#define BATTCRYPT_H

#include "common.h"

extern "C" int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);

#endif
