SUBDIRS=src

AUTOMAKE_OPTIONS=foreign

bin_PROGRAMS=test

test_SOURCES=test.c
test_LDADD = @ADD_LIBS@ -lwandder
test_LDFLAGS=-L"$(top_srcdir)/src/.libs"
test_CFLAGS=-I"$(top_srcdir)/src"
