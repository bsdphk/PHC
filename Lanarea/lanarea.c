#include "lanarea.h"

#define ROL(value, shift) (value << (shift % sizeof(value))) | (value >> (sizeof(value) * 8 - (shift % sizeof(value))))
#define ROR(value, shift) (value >> (shift % sizeof(value))) | (value << (sizeof(value) * 8 - (shift % sizeof(value))))

static inline size_t diagonal_ur (size_t i, size_t w);
//static inline size_t diagonal_dr (size_t i, size_t w, size_t h);

const uint8_t pi[] =	{
			0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
			0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34,
			0x4A, 0x40, 0x93, 0x82, 0x22, 0x99, 0xF3, 0x1D,
			0x00, 0x82, 0xEF, 0xA9, 0x8E, 0xC4, 0xE6, 0xC8,
			0x94, 0x52, 0x82, 0x1E, 0x63, 0x8D, 0x01, 0x37,
			0x7B, 0xE5, 0x46, 0x6C, 0xF3, 0x4E, 0x90, 0xC6,
			0xCC, 0x0A, 0xC2, 0x9B, 0x7C, 0x97, 0xC5, 0x0D,
			0xD3, 0xF8, 0x4D, 0x5B, 0x5B, 0x54, 0x70, 0x91,
			0x79, 0x21, 0x6D, 0x5D, 0x98, 0x97, 0x9F, 0xB1,
			0xBD, 0x13, 0x10, 0xBA, 0x69, 0x8D, 0xFB, 0x5A,
			0xC2, 0xFF, 0xD7, 0x2D, 0xBD, 0x01, 0xAD, 0xFB,
			0x7B, 0x8E, 0x1A, 0xFE, 0xD6, 0xA2, 0x67, 0xE9,
			0x6B, 0xA7, 0xC9, 0x04, 0x5F, 0x12, 0xC7, 0xF9,
			0x92, 0x4A, 0x19, 0x94, 0x7B, 0x39, 0x16, 0xCF,
			0x70, 0x80, 0x1F, 0x2E, 0x28, 0x58, 0xEF, 0xC1,
			0x66, 0x36, 0x92, 0x0D, 0x87, 0x15, 0x74, 0xE6
			};

const uint8_t e[] =	{
			0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
			0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
			0x76, 0x2E, 0x71, 0x60, 0xF3, 0x8B, 0x4D, 0xA5,
			0x6A, 0x78, 0x4D, 0x90, 0x45, 0x19, 0x0C, 0xFE,
			0xF3, 0x24, 0xE7, 0x73, 0x89, 0x26, 0xCF, 0xBE,
			0x5F, 0x4B, 0xF8, 0xD8, 0xD8, 0xC3, 0x1D, 0x76,
			0x3D, 0xA0, 0x6C, 0x80, 0xAB, 0xB1, 0x18, 0x5E,
			0xB4, 0xF7, 0xC7, 0xB5, 0x75, 0x7F, 0x59, 0x58,
			0x49, 0x0C, 0xFD, 0x47, 0xD7, 0xC1, 0x9B, 0xB4,
			0x21, 0x58, 0xD9, 0x55, 0x4F, 0x7B, 0x46, 0xBC,
			0xED, 0x55, 0xC4, 0xD7, 0x9F, 0xD5, 0xF2, 0x4D,
			0x66, 0x13, 0xC3, 0x1C, 0x38, 0x39, 0xA2, 0xDD,
			0xF8, 0xA9, 0xA2, 0x76, 0xBC, 0xFB, 0xFA, 0x1C,
			0x87, 0x7C, 0x56, 0x28, 0x4D, 0xAB, 0x79, 0xCD,
			0x4C, 0x2B, 0x32, 0x93, 0xD2, 0x0E, 0x9E, 0x5E,
			0xAF, 0x02, 0xAC, 0x60, 0xAC, 0xC9, 0x3E, 0xD8
			};

int lanarea (
void *out,		// pointer to large enough dest
size_t outlen,		// must be a multiple of 32
const void *in,		// source password
size_t inlen,		// length of source password
const void *salt,	// cryptographic salt
size_t saltlen,		// length of salt
size_t t_cost,		// abstract amount of time to waste
size_t m_cost		// abstract amount of memory to waste
) {
	// check that directions were followed and that pointers are valid
	if (!out || !outlen || (outlen % 32) || !in || !inlen || !salt || !saltlen) {
		return 2;
	}

	// check for idiocy
	if (!m_cost || !t_cost) {
		memset (out, 0x00, outlen);	// contrary to popular belief, there are stupid
		return 1;			// queries, and they deserve stupid answers
	}

	// initialization
	m_cost = m_cost * 16;
	size_t x, y;
	uint8_t **matrix = malloc (m_cost * sizeof (uint8_t *));

	// matrix size parameters
	const size_t columnSize		= m_cost;
	const size_t rowSize		= 16;
	const size_t matrixSize		= columnSize * rowSize;

	// memory allocation
	for (x = 0; x < m_cost; x++) {
		matrix[x] = malloc (rowSize * sizeof (uint8_t));
	}

	// allocate additional important memory
	uint8_t *hash	= malloc (32 * sizeof (uint8_t));
	uint8_t *line	= malloc (rowSize * sizeof (uint8_t));
	uint8_t *row	= malloc (rowSize * sizeof (uint8_t));
	uint8_t *column	= malloc (columnSize * sizeof (uint8_t));
	uint8_t *chain	= malloc (matrixSize * sizeof (uint8_t));

	const size_t initialSize = (sizeof pi) + (sizeof e) + 32;

	uint8_t *initial	= malloc (initialSize * sizeof (uint8_t));

	// copy constants over
	size_t offset = 0;
	memcpy (initial + offset, pi, sizeof pi);
	offset += sizeof pi;
	memcpy (initial + offset,  e, sizeof  e);
	offset += sizeof  e;

	memset (initial + offset, 0, 32);	// pad until sizeof BLAKE2b 256bit output

	// initialize the matrix
	for (x = 0; x < columnSize; x++) {
		for (y = 0; y < rowSize; y++) {
			blake2b (
				hash,
				initial,
				NULL,	// we don't need a key here
				32,	// give a 256 bit output
				initialSize,
				0
				);

			// append last hash after [e ++ pi]
			memcpy (initial + offset, hash, 32);

			// set the matrix byte
			matrix[x][y] = hash[y];
		}
	}

	// compute the initial line
	blake2b (
		hash,
		in,
		salt,
		32,
		inlen,
		saltlen
		);

	// actual processing
	t_cost = t_cost * 4;			// run the loop at least 4 times
	m_cost = m_cost * rowSize;		// (block count * block height) * block width = total bytes
	size_t z, r, c;
	for (x = 0; x < t_cost; x++) {
		for (y = 0; y < columnSize; y++) {
			// apply line to matrix
			for (z = 0; z < rowSize; z++) {
				// cause cache misses
				r = (y + hash[z]) % columnSize;	// prevent cache read hits
				c = (r + matrix[y][z]) % columnSize;	// ^^^^^^^^^^^^^^^^^^^^^^^
				r = (r + matrix[r][z]) % columnSize;	// ^^^^^^^^^^^^^^^^^^^^^^^
				c = matrix[c][z];

				// rotate right or left ...
				// ... although it really only
				// matters for one or two cases
				switch (c % 2) {
					case 0x00:
						c = ROL (c, r);
						break;
					case 0x01:
						c = ROR (c, r);
						break;
				}

				// mix mixing instructions
				switch (c % 4) {
					case 0x00:	// ADD
						matrix[y][z] = matrix[y][z] + hash[z];
						break;
					case 0x01:	// XOR
						matrix[y][z] = matrix[y][z] ^ hash[z];
						break;
					case 0x02:	// SUB
						matrix[y][z] = matrix[y][z] - hash[z];
						break;
					case 0x03:	// XNOR
						matrix[y][z] = matrix[y][z] ^ ~hash[z];
						break;
				}
			}


			// build a chain using the up-right diagonal full matrix
			for (z = 0; z < m_cost; z++) {
				c = z % rowSize;
				r = diagonal_ur (z, rowSize);
				chain[z] = matrix[r][c];
			}

			// hash the chain
			blake2b (hash, chain, NULL, 32, matrixSize, 0);

		// rinse and repeat - minus the rinsing :)
		}
	// do this as many times as is necessary to waste compute time
	}

	// create and dump the output
	outlen = outlen / 32;
	for (x = 0; x < outlen; x++) {
		y = x * 32;	// offset for output
		blake2b (((uint8_t *) out) + y, chain, hash, 32, matrixSize, 32);	// hash the matrix using the last hash as a key
		memcpy (hash, ((uint8_t *) out) + y, 32);	// copy the output back to prevent a WAR data hazard
	}

	// cleanup all of our memory allocations
	m_cost = m_cost / rowSize;	// undo earlier multiply
	for (x = 0; x < m_cost; x++) {
		free (matrix[x]);
	}
	free (matrix);
	free (hash);
	free (line);
	free (row);
	free (column);
	free (chain);
	free (initial);

	return 0;
}

// Creates the up-right diagonal pattern
static inline size_t diagonal_ur (size_t i, size_t w) {
	// http://stackoverflow.com/questions/22647907/multidimensional-array-patterned-access/22648975#22648975

	// Simplification is left as an exercise for the compiler.
	return (((w - i % w) % w) + (i / w)) % w  + (w * (i / (w * w)));
}

int PHS (void *out, size_t outlen, const void *in, size_t inlen,
		const void *salt, size_t saltlen, unsigned int t_cost,
		unsigned int m_cost) {

	return lanarea (out, outlen, in, inlen, salt, saltlen, t_cost, m_cost);
}
