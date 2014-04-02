cfuge: cfuge.o cfuge-main.o 
	gcc -o cfuge cfuge.o cfuge-main.o -lcrypto -O3 -std=c99

cfuge.o: cfuge.c cfuge.h
	gcc -c cfuge.c -O3 -std=c99

cfuge-main.o: cfuge-main.c cfuge.h
	gcc -c cfuge-main.c -O3 -std=c99