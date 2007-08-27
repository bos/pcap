AC_INIT([Pcap],[0.3],[bos@serpentine.com], [pcap])

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
