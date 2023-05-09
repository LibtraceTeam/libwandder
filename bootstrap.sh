#! /bin/sh

set -x
aclocal
libtoolize --force --copy || glibtoolize --force --copy
autoheader
automake --add-missing --copy --foreign
autoconf
