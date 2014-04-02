/*
aes.h - AES functions for use in EARWORM
Written in 2013 by Daniel Franke <dfoxfranke@gmail.com>

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software to the
public domain worldwide. This software is distributed without any
warranty.

You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef EARWORM_AES_H
#define EARWORM_AES_H

#include <stdint.h>

typedef struct {
  uint32_t key[60];
} aeskey_t;

void earworm_aesenc_round(uint8_t *block, const uint8_t *roundkey);
void earworm_aes256enc_keysetup(const uint8_t *userkey, aeskey_t *key);
void earworm_aes256enc(uint8_t *block, const aeskey_t *key);

#endif
