CCFLAGS_REL = -O2
CCFLAGS_DBG = -g3 -DPHC_DEBUG_OUTPUT $(CCFLAGS_REL)
CCFLAGS = --std=gnu99 -pedantic -lcrypto -lm -Wall
CFILES = phc.c phc_demo.c

all: phc tvgen


tvgen : phc.c phc_tv.c
	gcc $(CCFLAGS_REL) phc.c phc_tv.c -o phc_ivgen $(CCFLAGS)

debugstat : $(CFILES)
	gcc $(CCFLAGS_DBG) -DPHC_DEBUG_STATISTICS $(CFILES) -o phc_demo $(CCFLAGS)

debug : $(CFILES)
	gcc $(CCFLAGS_DBG) $(CFILES) -o phc_demo $(CCFLAGS)

phcstat : $(CFILES)
	gcc $(CCFLAGS_REL) -DPHC_DEBUG_STATISTICS $(CFILES) -o phc_demo $(CCFLAGS)

phc: $(CFILES)
	gcc $(CCFLAGS_REL) $(CFILES) -o phc_demo $(CCFLAGS)

clean:
	rm -rf phc_demo phc_ivgen
