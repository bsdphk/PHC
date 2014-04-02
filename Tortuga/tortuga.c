#include <math.h>
#include <string.h>

#include "turtle.h"

#ifndef TORTUGA_SALT_BYTES
#define TORTUGA_SALT_BYTES    16
#endif

#ifndef TORTUGA_MIN_KEY_BYTES
#define TORTUGA_MIN_KEY_BYTES 16
#endif

#ifdef TORTUGA_DEBUG
#include <stdio.h>
#endif

static unsigned int upper_power_of_four(const unsigned int v) {

	const unsigned int temp = 1 << ((unsigned int) ceil(log2(v)));

	return ((const unsigned int) log2(temp)) & 1 ? temp << 1 : temp;
}

static unsigned char * encode_uint_(unsigned char * res, const unsigned int x) {

	res[0] =  x        & 0xFF;
	res[1] = (x >>  8) & 0xFF;
	res[2] = (x >> 16) & 0xFF;
	res[3] = (x >> 24) & 0xFF;

	return res;
}

static void tortuga_genkey(unsigned char * key , const unsigned int  key_size,
                     const unsigned char * salt, const unsigned int salt_size) {

	unsigned char salt_[TORTUGA_SALT_BYTES];

	unsigned int i, len = key_size >> 2;

	unsigned char tmp[4];
	unsigned char backup[key_size];

	memset(salt_, 0, TORTUGA_SALT_BYTES);
	memcpy(salt_, salt, salt_size < TORTUGA_SALT_BYTES ? salt_size : TORTUGA_SALT_BYTES);

	for (i = 0; i < len; ++i)
		turtle(&backup[i << 2], encode_uint_(tmp,i), sizeof(tmp), 1, 0, salt_, TORTUGA_SALT_BYTES);

	for (i = 0; i < key_size; ++i)
		key[i] ^= backup[i];

	if (salt_size > TORTUGA_SALT_BYTES)
		tortuga_genkey(key, key_size, salt + TORTUGA_SALT_BYTES, salt_size - TORTUGA_SALT_BYTES);

}

unsigned int tortuga_internal_key_size(const unsigned int m_cost) {

	const unsigned int key_bytes_ = upper_power_of_four(m_cost + 1);

	return key_bytes_ < TORTUGA_MIN_KEY_BYTES ? TORTUGA_MIN_KEY_BYTES : key_bytes_;
}

void tortuga(unsigned char * out  , const unsigned int   out_size,
       const unsigned char * input, const unsigned int input_size,
       const unsigned char * salt , const unsigned int  salt_size,
 const unsigned int t_cost, const unsigned int m_cost) {

	unsigned int ipos, ilen, i, counter = 0;

	/* Waste memory. */
	const unsigned int key_bytes = tortuga_internal_key_size(m_cost);

	const unsigned int min_iterations = ((t_cost * TORTUGA_MIN_KEY_BYTES) / key_bytes + 1) << 1;

	const unsigned int   state_size = sqrt(key_bytes);
	const unsigned int message_size = state_size >> 2;

	unsigned char state[state_size];
	unsigned char   key[key_bytes ];

	memset(key  , 0, sizeof(key  ));
	memset(state, 0, sizeof(state));

	/* Prevent length extension attacks. */
	tortuga_genkey(encode_uint_(key  ,  salt_size), sizeof(key  )      , salt, salt_size  );
	turtle_inplace(encode_uint_(state, input_size), sizeof(state), 1, 0, key , sizeof(key));

	for (ipos = 0; ipos < input_size; ipos += message_size /*, ++counter */ ) {

		ilen = input_size - ipos < message_size ? input_size % message_size : message_size;

		for (i = 0; i < ilen; ++i)
			state[i] ^= input[ipos + i];

		/* Absorb some bytes. */
		turtle_inplace(state, sizeof(state), 1, 0, key, sizeof(key));
	}

	/* Waste time. */
	while (counter++ < min_iterations)
		turtle_inplace(state, sizeof(state), 1, 0, key, sizeof(key));

	for (i = 0; i + message_size < out_size; i += message_size) {

		/* Squeeze some bytes. */
		memcpy(out + i, state, message_size);
		turtle_inplace(state, sizeof(state), 1, 0, key, sizeof(key));
	}

	/* Squeeze last bytes. */
	memcpy(out + i, state, out_size - i);

#ifdef TORTUGA_DEBUG

	printf("key_bytes:       %u\n", key_bytes     );
	printf("min_iterations:  %u\n", min_iterations);
	printf("state_size:      %u\n", state_size    );
	printf("message_size:    %u\n", message_size  );

#endif

}
