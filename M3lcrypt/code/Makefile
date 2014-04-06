SOURCES= Sha2.c m3lcrypt.c main.c
LINK=cc
INCLUDES=
CFLAGS=-D_HF=0 -D_VSPACE=16 -O2
SLIBS=
PROGRAM= m3lcrypt

OBJECTS = $(SOURCES:.c=.o)
debug:= -g 

all debug: $(PROGRAM)

$(PROGRAM): $(INCLUDES) $(OBJECTS)
	$(LINK) -o $@ $(OBJECTS) $(SLIBS)
	rm -f $(OBJECTS)

.for SRC in $(SOURCES)
$(SRC:.c=.o): $(INCLUDES) $(SRC) 
	$(LINK) $(CFLAGS) -c -o $@ $(SRC) $(SLIBS) 
.endfor 

clean:
	rm -f $(PROGRAM)
