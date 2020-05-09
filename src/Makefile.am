lib_LTLIBRARIES=libwandder.la
include_HEADERS=libwandder.h libwandder_etsili.h

libwandder_la_SOURCES=encoder.c decoder.c libwandder.h libwandder_etsili.c \
        libwandder_etsili.h itemhandler.c itemhandler.h wandder_internal.h

libwandder_la_LIBADD = @ADD_LIBS@
libwandder_la_LDFLAGS = @ADD_LDFLAGS@ -version-info 2:0:0
libwandder_la_CPPFLAGS = -Werror

