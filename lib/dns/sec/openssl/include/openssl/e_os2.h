/* e_os2.h */

#ifndef OPENSSL_E_OS2_H
#define OPENSSL_E_OS2_H 1

#ifdef  __cplusplus
extern "C" {
#endif

/* Definitions of OPENSSL_GLOBAL and OPENSSL_EXTERN,
   to define and declare certain global
   symbols that, with some compilers under VMS, have to be defined and
   declared explicitely with globaldef and globalref.  On other OS:es,
   these macros are defined with something sensible. */

#if defined(VMS) && !defined(__DECC)
# define OPENSSL_EXTERN globalref
# define OPENSSL_GLOBAL globaldef
#else
# define OPENSSL_EXTERN extern
# define OPENSSL_GLOBAL
#endif

#ifdef  __cplusplus
}
#endif
#endif /* OPENSSL_E_OS2_H */

