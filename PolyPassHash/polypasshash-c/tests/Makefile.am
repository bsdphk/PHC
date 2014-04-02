AM_CFLAGS = -I$(top_builddir)/include -lcrypto

TESTS = check_libgfshare check_libpolypasshash check_libpph_thresholdless\
				check_libpph_partialbytes check_libpph_phc

check_PROGRAMS = check_libgfshare check_libpolypasshash\
								 check_libpph_thresholdless check_libpph_partialbytes\
								 check_libpph_phc

check_libgfshare_SOURCES = check_libgfshare.c\
													$(top_builddir)/include/libgfshare.h\
												$(top_builddir)/include/libgfshare_tables.h
check_libgfshare_CFLAGS = @CHECK_CFLAGS@ -I../include
check_libgfshare_LDADD = $(top_builddir)/lib/libgfshare.la @CHECK_LIBS@

check_libpolypasshash_SOURCES = check_libpolypasshash.c\
																$(top_builddir)/include/libgfshare.h\
																$(top_builddir)/include/libpolypasshash.h
check_libpolypasshash_CFLAGS = @CHECK_CFLAGS@ -I$(top_builddir)/include
check_libpolypasshash_LDADD = $(top_builddir)/lib/libgfshare.la\
															$(top_builddir)/src/libpolypasshash.la\
															@CHECK_LIBS@

check_libpph_thresholdless_SOURCES = check_libpph_thresholdless.c\
																$(top_builddir)/include/libgfshare.h\
																$(top_builddir)/include/libpolypasshash.h

check_libpph_thresholdless_CFLAGS= @CHECK_CFLAGS@ -I$(top_builddir)/include
check_libpph_thresholdless_LDADD = $(top_builddir)/lib/libgfshare.la\
																	 $(top_builddir)/src/libpolypasshash.la\
																	 @CHECK_LIBS@

check_libpph_partialbytes_SOURCES= check_libpph_partialbytes.c\
																$(top_builddir)/include/libgfshare.h\
																$(top_builddir)/include/libpolypasshash.h

check_libpph_partialbytes_CFLAGS= @CHECK_CFLAGS@ -I$(top_builddir)/include
check_libpph_partialbytes_LDADD = $(top_builddir)/lib/libgfshare.la\
																	 $(top_builddir)/src/libpolypasshash.la\
																	 @CHECK_LIBS@

check_libpph_phc_SOURCES= check_libpph_phc.c\
													$(top_builddir)/include/libgfshare.h\
												  $(top_builddir)/include/libpolypasshash.h

check_libpph_phc_CFLAGS= @CHECK_CFLAGS@ -I$(top_builddir)/include
check_libpph_phc_LDADD = $(top_builddir)/lib/libgfshare.la\
												 $(top_builddir)/src/libpolypasshash.la\
												 @CHECK_LIBS@
