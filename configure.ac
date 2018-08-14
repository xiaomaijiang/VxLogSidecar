#指定最低的Autoconf版本为2.69
AC_PREREQ([2.69])

#指定应用名称、版本、邮箱地址
AC_INIT(main, 1.0, 15875339926@139.com)

#检查Automake的必要工具
AM_INIT_AUTOMAKE(foreign -Wall)
AC_CONFIG_SRCDIR([src/core/main.c])
AC_CONFIG_HEADERS([config.h])

# APR
AC_ARG_VAR([APRCONFIG], [apr-1-config tool with path])

if test -z "$APRCONFIG"; then
	AC_PATH_PROG(apr_config, [apr-1-config])
else
	apr_config=$APRCONFIG
fi

if test "x$apr_config" = "x"; then
    AC_MSG_ERROR([apr library not found])
fi

APR_LIBS=`$apr_config --link-ld --libs`
LIBS="$LIBS $APR_LIBS "

APR_CFLAGS=`$apr_config --cppflags`
CFLAGS="$CFLAGS $APR_CFLAGS  "

APR_LDFLAGS=`$apr_config --ldflags`
LDFLAGS="$LDFLAGS $APR_LDFLAGS "

APR_INCLUDES=`$apr_config --includes`
INCLUDES="$INCLUDES $APR_INCLUDES"

# Checks for programs.
AC_PROG_CC
# APR

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/core/Makefile])
AC_SUBST(INCLUDES)
AC_SUBST(APR_LIBS)
AC_SUBST(APR_CFLAGS)

AC_OUTPUT
