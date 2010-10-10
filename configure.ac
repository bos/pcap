AC_INIT([Pcap],[0.4.5.1],[bos@serpentine.com], [pcap])

AC_ARG_WITH(compiler,
  [AS_HELP_STRING([--with-compiler],
    [use the given Haskell compiler])],
  compiler="$withval",
  compiler=ghc)dnl

AC_CONFIG_HEADER(include/pcapconfig.h)

AC_CHECK_MEMBERS([struct sockaddr.sa_len])

case "$host" in
*-mingw32)
    EXTRA_LIBS=wsock32
    CALLCONV=stdcall
    ;;
*)
    EXTRA_LIBS=pcap
    CALLCONV=ccall
    ;;
esac

AC_SUBST([CALLCONV])
AC_SUBST([EXTRA_LIBS])

AC_CONFIG_FILES([pcap.buildinfo])

AC_OUTPUT
