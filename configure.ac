# Super primitive configure script

AC_INIT(libwandder, 2.0.13, shane@alcock.co.nz)

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR(src/decoder.c)
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PREFIX_DEFAULT(/usr/local)

AC_PROG_CC
AC_PROG_INSTALL

LT_INIT
gcc_PACKED

EXTRA_LIBS=""

AC_CHECK_LIB([m], [ceil],,math_found = 0)
AC_CHECK_LIB([pthread], [pthread_mutex_trylock],,pthread_found=0)
AC_CHECK_LIB([crypto], [OPENSSL_init_crypto], , [have_libcrypto="0"])

AC_CHECK_HEADERS([uthash.h], [uthash_avail=yes; break;])
AS_IF([test "x$uthash_avail" != "xyes"],
        [AC_MSG_ERROR([Required header uthash.h not found; install uthash and try again])])

AC_CONFIG_FILES([Makefile src/Makefile])

if test "$math_found" = 0; then
        AC_MSG_ERROR(Required library libm not found; use LDFLAGS to specify library location)
fi

if test "$pthread_found" = 0; then
        AC_MSG_ERROR(Required library libpthread not found; use LDFLAGS to specify library location)
fi


AC_SUBST([ADD_LIBS])
AC_SUBST([EXTRA_LIBS])
AC_SUBST([ADD_LDFLAGS])
AC_SUBST([ADD_INCLS])
AC_SUBST([LTLIBOBJS])

AC_OUTPUT

# Function for reporting whether an option was set or not
reportopt() {
        if test x"$2" = xtrue -o x"$2" = xyes; then
                AC_MSG_NOTICE([$1: Yes])
        else 
                AC_MSG_NOTICE([$1: No])
        fi
}

