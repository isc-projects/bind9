/* define if you need inet_aton() */
#undef NEED_INET_ATON

/* define if you need inet_ntop() */
#undef NEED_INET_NTOP

/* define if you need inet_pton() */
#undef NEED_INET_PTON

/* define if you need AF_INET6 */
#undef NEED_AF_INET6

/* Probably not the right place... */
#ifdef NEED_AF_INET6
#define AF_INET6 99
#endif
