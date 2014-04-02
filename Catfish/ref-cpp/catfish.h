#include <assert.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

class CatFish {
 public:
  typedef struct {
      BN_CTX* ctx;
      BIGNUM* p;
      BIGNUM* q;
      BIGNUM* n;
      BIGNUM* g;
      int t_cost;
      int m_cost;
      BIGNUM* bn_m_cost;
  } CatfishParameters;

  CatFish (int t_cost, int m_cost, string p, string q, string n, string g);

  ~CatFish ();

  string Digest (string salt, string password);

 protected:
  void H (unsigned char* input, int input_len, BIGNUM* output);
  void KeccakWrapper (unsigned char* input, int input_len, BIGNUM* output, int KKeccakOutputLen);

 private:
  // Two states are kept during the computation as Keccak prefers "unsigned char*"
  // and BN_mod_exp prefers BIGNUM. These states are sync-ed up here.
  void SyncStates(unsigned char* state, int state_len, BIGNUM* bn_state);
  CatfishParameters params_;
};
