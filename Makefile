CC=gcc
CPP=g++
CFLAGS=-Wall -march=native -std=gnu99
CPPFLAGS=-Wall -march=native
CLIBS=-pthread -lcrypto -lm
CPPLIBS=-pthread -lm
OPT_CFLAGS=-O3
DEV_CFLAGS=-g

BATTCRYPT=Battcrypt/code/c++
CATENA=Catena/code/src
GAMBIT=Gambit/src
LYRA=Lyra2/src/sse
M3LCRYPT=M3lcrypt/code
TWOCATS=TwoCats/twocats
YESCRYPT=Yescrypt/yescrypt-0.5

EXE=phs-antcrypt phs-argon phs-battcrypt phs-catena phs-centrifuge \
phs-earworm phs-gambit phs-lanarea phs-lyra phs-m3lcrypt phs-makwa phs-mcsphs \
phs-omegacrypt phs-parallela phs-polypasshash phs-pomelo phs-pufferfish phs-rig \
phs-schvrch phs-tortuga phs-twocats phs-yarn phs-yescrypt

default: opt

opt: CFLAGS += $(OPT_CFLAGS)
opt: CPPFLAGS += $(OPT_CFLAGS)
opt: all

debug: CFLAGS += $(DEV_CFLAGS)
debug: CPPFLAGS += $(DEV_CFLAGS)
debug: all

all: $(EXE)

phs-antcrypt: main.c limits/antcrypt-limits.c AntCrypt/source/phc.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

#phs-argon: main.c limits/argon-limits.c Argon/Reference_implementation/argon-ref.cpp
	#$(CPP) $(CPPFLAGS) -o $@ $^

phs-argon: main.c limits/argon-limits.c Argon/Argon-Optimized/Linux-AES-NI/Argon-Optimized.cpp
	$(CPP) $(CPPFLAGS) -maes -mavx -std=c++11 -o $@ $^ $(CPPLIBS)

phs-battcrypt: main.c limits/battcrypt-limits.c  $(BATTCRYPT)/battcrypt.cpp $(BATTCRYPT)/blowfish.cpp $(BATTCRYPT)/sha512.cpp
	$(CPP) $(CPPFLAGS) -o $@ $^ $(CPPLIBS)

phs-catena: main.c limits/catena-limits.c $(CATENA)/catena.c $(CATENA)/catena-blake2b.c $(CATENA)/blake2/blake2b.c
	$(CC) $(CFLAGS) -fgnu89-inline -I$(CATENA)/blake2 -o $@ $^ $(CLIBS)

phs-centrifuge: main.c limits/centrifuge-limits.c Centrifuge/cfuge.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

phs-earworm: main.c limits/earworm-limits.c EARWORM/aes.c EARWORM/core-opt.c EARWORM/phc.c EARWORM/sha256.c EARWORM/util-opt.h
	$(CC) $(CFLAGS) -DEARWORM_BUILD_OPT -o $@ $^ $(CLIBS)

phs-gambit: main.c limits/gambit-limits.c $(GAMBIT)/gambit.cpp $(GAMBIT)/keccak.cpp
	$(CPP) $(CPPFLAGS) -o $@ $^ $(CPPLIBS)

phs-lanarea: main.c limits/lanarea-limits.c Lanarea/lanarea.c
	(cd Lanarea/libb2; autoreconf; automake --add-missing; ./configure && make)
	$(CC) $(CFLAGS) -o $@ $^ Lanarea/libb2/src/.libs/libb2_la-blake2b.o $(CLIBS)

phs-lyra: main.c limits/lyra-limits.c $(LYRA)/Sponge.c $(LYRA)/Lyra2.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

phs-m3lcrypt: main.c limits/m3lcrypt-limits.c $(M3LCRYPT)/Sha2.c $(M3LCRYPT)/m3lcrypt.c
	$(CC) $(CFLAGS) -D_HF=0 -D_VSPACE=16 -o $@ $^ $(CLIBS)

phs-makwa: main.c limits/makwa-limits.c Makwa/c/makwa.c Makwa/c/phc.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

phs-mcsphs: main.c limits/mcsphs-limits.c MCS_PHS/code/mcs_psw/mcs_psw.cpp MCS_PHS/code/mcssha8/mcssha8.cpp
	$(CPP) $(CPPFLAGS) -o $@ $^ $(CPPLIBS)

phs-omegacrypt: main.c limits/omegacrypt-limits.c OmegaCrypt/chacha-wrapper.c OmegaCrypt/cubehash.c OmegaCrypt/ocrypt.c OmegaCrypt/nettle-chacha/chacha-init.c OmegaCrypt/nettle-chacha/chacha-crypt.c OmegaCrypt/nettle-chacha/chacha-core-internal.c OmegaCrypt/nettle-chacha/memxor.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

phs-parallela: main.c limits/parallela-limits.c Parallel/code/c++/parallel.cpp Parallel/code/c++/sha512.cpp
	$(CPP) $(CPPFLAGS) -o $@ $^ $(CPPLIBS)

phs-pomelo: main.c limits/pomelo-limits.c POMELO/pomelo.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

# This one is not built by default since it seems to require setup functions be called
# before PHS.
phs-polypasshash: main.c limits/polypasshash-limits.c PolyPassHash/polypasshash-c/src/libpolypasshash.c PolyPassHash/polypasshash-c/lib/libgfshare.c
	$(CC) $(CFLAGS) -IPolyPassHash/polypasshash-c/include -o $@ $^ $(CLIBS)

phs-pufferfish: main.c limits/pufferfish-limits.c Pufferfish/src/optimized/pufferfish.c Pufferfish/src/optimized/sha512.c Pufferfish/src/optimized/hmac-sha512.c Pufferfish/src/common/itoa64.c Pufferfish/src/common/api.c
	$(CC) $(CFLAGS) -DOPTIMIZED -o $@ $^ $(CLIBS)

phs-rig: main.c limits/rig-limits.c RIG/source/rig.cpp RIG/source/BLAKE/blake2b-ref.c
	$(CPP) $(CPPFLAGS) -o $@ $^ $(CPPLIBS)

phs-schvrch: main.c limits/schvrch-limits.c Schvrch/schvrch.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

phs-tortuga: main.c limits/tortuga-limits.c Tortuga/turtle.c Tortuga/tortuga.c Tortuga/phs.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

phs-twocats: main.c limits/twocats-limits.c $(TWOCATS)/twocats-common.c $(TWOCATS)/twocats-blake2s.c $(TWOCATS)/twocats-blake2b.c $(TWOCATS)/twocats-sha256.c $(TWOCATS)/twocats-sha512.c $(TWOCATS)/twocats.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

phs-yarn: main.c limits/yarn-limits.c Yarn/yarn.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

phs-yescrypt: main.c limits/yescrypt-limits.c $(YESCRYPT)/yescrypt-best.c $(YESCRYPT)/yescrypt-common.c $(YESCRYPT)/sha256.c $(YESCRYPT)/phc.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

clean:
	rm -f $(EXE)
