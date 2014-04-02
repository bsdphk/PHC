## src-specific makefile
AM_LDFLAGS = -lcrypto
AM_CFLAGS = -I$(top_builddir)/include

lib_LTLIBRARIES = libpolypasshash.la
libpolypasshash_la_SOURCES = libpolypasshash.c\
														 $(top_builddir)/include/libgfshare.h\
														 $(top_builddir)/include/libpolypasshash.h
libpolypasshash_la_LIBADD = $(top_builddir)/lib/libgfshare.la
	

bin_PROGRAMS = polypasshash
polypasshash_SOURCES = polypasshash.c 
polypasshash_CFLAGS = -I$(top_builddir)/include/
polypasshash_LDADD = $(top_builddir)/src/libpolypasshash.la
