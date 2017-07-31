#ifndef _EDDSA_H_
#define _EDDSA_H_ 1

#ifndef CKK_EDDSA
#ifdef PK11_SOFTHSMV2_FLAVOR
#define CKK_EDDSA               0x00008003UL
#endif
#endif

#ifndef CKM_EDDSA_KEY_PAIR_GEN
#ifdef PK11_SOFTHSMV2_FLAVOR
#define CKM_EDDSA_KEY_PAIR_GEN         0x00009040UL
#endif
#endif

#ifndef CKM_EDDSA
#ifdef PK11_SOFTHSMV2_FLAVOR
#define CKM_EDDSA                      0x00009041UL
#endif
#endif

#endif /* _EDDSA_H_ */
