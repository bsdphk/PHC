#include <assert.h>
#include <iostream>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "catfish.h"

string unhexify(string hex_str) {
  string regular_str;
  for (int i = 0; i < hex_str.size(); i += 2) {
    regular_str += char(strtol(hex_str.substr(i, 2).c_str(), NULL, 16));
  }
  return regular_str;
}

void test () {
  CatFish cf(2, 1024, 
             "", // p
             "", // q
             "432F0BC10EDA1D0538E16FD4C1882C01736D2EBB4A21CA00F8DE508551C6AFF678BA19E7A9162C00C993CE4FB251BAB10981DABF84154DDF7C53C7B3CC987165BCFFCE39A4FCBAD83E1A8BBB11A6FF928E09AAC05037A21636A6671ACFED77D7E109B243F5BA9B5CCE8AA56E85914785096F33BCA9EBAC78D074E52A69F8C82B", // n
             "1F91B2B37B136F3886DF5C6871551EB9C8977ADE58B77693999A30D8AD11FC0043D9AD55451DFC2F805D46DEA4B5D3B631AC841C8D46CAE8CDD40E1EE8E036A6C6ACDAD4E7F06523203195FD78A9D541240A18AFE024DC9E0F241017E99D59045D8D3B8CB3D91859A71F027E22773B0B14057D59383C4EAAD0B49382BBFA5665" // g
             );
  cout << "hash:" << cf.Digest(unhexify("4c880aa553669c3869f62b389c2c3499"), "The quick brown fox jumps over the lazy dog") << "\n";
}

int main(int argc, char* argv[]){
  clock_t t1, t2;
  t1=clock();
  int repeats = 10;
  for (int i = 0; i < repeats; ++i) {
    test();
  }
  t2=clock();
  double elapsed_secs = double((float)t2 - (float)t1) / (CLOCKS_PER_SEC * repeats);
  cout << "Elapsed Time in Seconds: " << elapsed_secs << endl;
  return 1;
}
