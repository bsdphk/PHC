#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

void stir(uint64_t * state, uint64_t statelen, int rounds)
{
	const uint64_t mixer = 6148914691236517205;//010101...
	uint64_t carry = 1234567890123456789;
	int i;
	uint64_t j;
	
	for(i = 0; i < rounds; i++)
	{
		for(j = 0; j < statelen; j++)
		{
			if(state[(j+2)%statelen]>state[(j+3)%statelen])
				carry ^= state[(j+1)%statelen];
			else
				carry ^= ~state[(j+1)%statelen];

			state[j] ^= carry;
			carry += mixer;
		}
	}
}

void revolve(uint64_t * state, int statelen, uint64_t rounds)
{
	uint64_t i;
	uint64_t carry = 0;
	int j;
		
	for(i = 0; i < rounds; i++)
	{
		for(j = 0; j < statelen; j++)
		{
			if(state[(j+2)%statelen]>state[(j+3)%statelen])
				carry ^= state[(j+1)%statelen];
			else
				carry ^= ~state[(j+1)%statelen];

			state[j] ^= carry;
		}
	}
}

void evolve(uint64_t * state, int statelen)
{
	int i, j;
	
	for(i = 0; i < (statelen * 2); i++)
	{	
		for(j = 0; j < (statelen); j++)
		{
			if(state[(j + 1) % statelen] > state[(j + 3) % statelen])
				state[j % statelen] ^=  state[(j + 1) % statelen];
			else
				state[j % statelen] ^=  ~state[(j + 1) % statelen];
			
			if(state[(j + 2) % statelen] > state[(j + 3) % statelen])
				state[j % statelen] ^=  state[(j + 2) % statelen];
			else
				state[j % statelen] ^=  ~state[(j + 2) % statelen];	
			
			if(state[(j + 3) % statelen] % 2 == 1)
				state[j % statelen] ^=  state[(j + 3) % statelen];
			else
				state[j % statelen] ^=  ~state[(j + 3) % statelen];	
		}
	}
}

int PHS(void *out, size_t outlen, 
		const void *in, size_t inlen, 
		const void *salt, size_t saltlen, 
		unsigned int t_cost, unsigned m_cost)
{
	int statelen = 256, j;
	uint64_t state[256] = {0};
	uint64_t memcost;
	memcost = (m_cost + 1) * statelen;
	uint64_t * memstate;
	uint64_t rounds = 4, i;
	
	memmove(&state[0], in, inlen);
	memmove(&state[(inlen / 8) + 1], salt, saltlen);
	state[statelen - 3] = outlen;
	state[statelen - 2] = inlen;
	state[statelen - 1] = saltlen;
	
	stir(state, statelen, rounds * 2);
		
	if(t_cost > 0)
		revolve(state, statelen, t_cost);
		
	if(m_cost > 0)
	{
		memstate = (uint64_t *) calloc(memcost, sizeof(uint64_t));
			
		memmove(memstate, state, statelen * sizeof(uint64_t));
		stir(memstate, memcost, rounds);
		
		for(i = 0; i < (memcost / statelen); i++)
		{
			for(j = 0; j < statelen; j++)
				state[j] = memstate[j * (i + 1)];
				
			revolve(state, statelen, 2);
		}
		free(memstate);
	}
	evolve(state, statelen);
	memmove(out, state, outlen);
	
	return 0;
}
