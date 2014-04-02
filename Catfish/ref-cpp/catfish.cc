#include <openssl/bn.h>
#include "KeccakSponge.h"
#include "catfish.h"

using namespace std;

CatFish::CatFish (int t_cost, int m_cost, string p, string q, string n, string g) {
  params_.t_cost = t_cost;
  params_.m_cost = m_cost;
  params_.ctx = BN_CTX_new();
  params_.p = BN_new();
  assert((size_t)BN_hex2bn(&params_.p, p.c_str()) == p.size());
  params_.q = BN_new();
  assert((size_t)BN_hex2bn(&params_.q, q.c_str()) == q.size());
  params_.n = BN_new();
  assert((size_t)BN_hex2bn(&params_.n, n.c_str()) == n.size());
  params_.g = BN_new();
  assert((size_t)BN_hex2bn(&params_.g, g.c_str()) == g.size());

  // If p and q are not specified, skip the inspection.
  if (p.size() + q.size() > 0) {
    BIGNUM* expected_n = BN_new();
    BN_mul(expected_n, params_.p, params_.q, params_.ctx);
    assert(BN_bn2hex(expected_n) == n);
    BN_free(expected_n);
  }

  params_.bn_m_cost = BN_new();
  char m_cost_buf[8];
  sprintf(m_cost_buf, "%d", m_cost);
  BN_dec2bn(&params_.bn_m_cost, m_cost_buf);
}

CatFish::~CatFish () {
  BN_CTX_free(params_.ctx);
  BN_free(params_.p);
  BN_free(params_.q);
  BN_free(params_.n);
  BN_free(params_.g);
  BN_free(params_.bn_m_cost);
}

string CatFish::Digest (string salt, string password) {
  assert(salt.size() == 16);
  assert(password.size() < 128);

  // Process inputs.
  // 16-byte + 16-byte + 128-byte = 160-byte.
  unsigned char* state = new unsigned char[160]; 
  int state_len = 160;
  memset(reinterpret_cast<void*>(state), 0, 160);
  // state[0] ... state[16]: salt.
  for (int i = 0; i < (int)salt.size(); ++i) {
    state[i] = salt[i];
  }
  // state[16] ... state[31]: str128(len(password)).
  state[16] = (int(password.size() * 8) & 0xff);
  state[17] = (int(password.size() * 8) >> 8);
  // state[32] ... state[159]: pad(password).
  for (int i = 32; i < (int)(32 + password.size()); ++i) {
    state[i] = password[i - 32];
  }

  // Setup local variables.
  BIGNUM* bn_state = BN_new();
  BIGNUM* idx = BN_new();
  BIGNUM** v = new BIGNUM* [1024];
  BIGNUM* ctr = BN_new();
  BN_zero(ctr);

  // Compute.
  for (int i = 0; i < params_.t_cost; ++i) {
    H(state, state_len, bn_state);
    state_len = 128;
    for (int j = 0; j < params_.m_cost; ++j) {
      v[j] = BN_new();
      BN_copy(v[j], bn_state);
      BN_add(ctr, ctr, BN_value_one());
      BN_GF2m_add(bn_state, bn_state, ctr);
      H(state, state_len, bn_state);
    }

    for (int j = 0; j < params_.m_cost; ++j) {
      BN_mod(idx, bn_state, params_.bn_m_cost, params_.ctx);
      BN_add(ctr, ctr, BN_value_one());
      BN_GF2m_add(bn_state, bn_state, ctr);
      BN_GF2m_add(bn_state, bn_state, v[atoi(BN_bn2dec(idx))]);
      H(state, state_len, bn_state);
    }
    BN_add(ctr, ctr, BN_value_one());
  }
  BN_GF2m_add(bn_state, bn_state, ctr);

  SyncStates(state, state_len, bn_state);
  KeccakWrapper(state, state_len, bn_state, 32);
  string tag(BN_bn2hex(bn_state));

  // Clean up.
  BN_free(bn_state);
  BN_free(idx);
  BN_free(ctr);
  for (int i = 0; i < 1024; ++i) {
    BN_free(v[i]);
  }
  delete v;
  delete[] state;

  return tag;
}

void CatFish::H (unsigned char* input, int input_len, BIGNUM* output) {
  if (input_len == 128) {
    // Skip the syncup for the first time for the user's input.
    // TODO: Get rid fo this hack.
    SyncStates(input, input_len, output);
  }
  KeccakWrapper(input, input_len, output, 128);
  BN_mod_exp(output, params_.g, output, params_.n, params_.ctx);
}

void CatFish::KeccakWrapper (unsigned char* input, int input_len, BIGNUM* output, int KKeccakOutputLen) {
  unsigned char keccak_output[KKeccakOutputLen];
  Keccak_SpongeInstance sponge;
  Keccak_SpongeInitialize(&sponge, 1024, 576);
  Keccak_SpongeAbsorb(&sponge, (unsigned char*)input, input_len);
  Keccak_SpongeSqueeze(&sponge, keccak_output, KKeccakOutputLen);

  string tmp_output;
  // Little Endian.
  for (int i = KKeccakOutputLen - 1 ; i >= 0; --i) {
    char buf[16];
    sprintf(buf, "%02x", keccak_output[i]);
    tmp_output.append(buf);
  }
  BN_hex2bn(&output, tmp_output.c_str());
}

// Two states are kept during the computation as Keccak prefers "unsigned char*"
// and BN_mod_exp prefers BIGNUM. These states are sync-ed up here.
void CatFish::SyncStates(unsigned char* state, int state_len, BIGNUM* bn_state) {
  // Little Endian.
  string tmp_state(BN_bn2hex(bn_state));
  // Zeros may be omitted by BN_bn2hex and we have to compensate.
  tmp_state = string(256 - tmp_state.size(), '0') + tmp_state;
  memset(reinterpret_cast<void*>(state), 0, 160);
  int l = state_len - 1;
  for(int k = 0; k < (int)tmp_state.size(); k += 2) {
    state[l] = (unsigned char)strtol(tmp_state.substr(k, 2).c_str(), NULL, 16);
    --l;
  }
}
