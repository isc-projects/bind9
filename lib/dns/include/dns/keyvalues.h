#ifndef DNS_KEYVALUES_H
#define DNS_KEYVALUES_H 1

ISC_LANG_BEGINDECLS

/*
 * Flags field of the KEY RR rdata
 */
#define NS_KEY_TYPEMASK		0xC000	/* Mask for "type" bits */
#define NS_KEY_TYPE_AUTH_CONF	0x0000	/* Key usable for both */
#define NS_KEY_TYPE_CONF_ONLY	0x8000	/* Key usable for confidentiality */
#define NS_KEY_TYPE_AUTH_ONLY	0x4000	/* Key usable for authentication */
#define NS_KEY_TYPE_NO_KEY	0xC000	/* No key usable for either; no key */
/* The type bits can also be interpreted independently, as single bits: */
#define NS_KEY_NO_AUTH		0x8000	/* Key unusable for authentication */
#define NS_KEY_NO_CONF		0x4000	/* Key unusable for confidentiality */
#define NS_KEY_RESERVED2	0x2000	/* Security is *mandatory* if bit=0 */
#define NS_KEY_EXTENDED_FLAGS	0x1000	/* reserved - must be zero */
#define NS_KEY_RESERVED4	0x0800	/* reserved - must be zero */
#define NS_KEY_RESERVED5	0x0400	/* reserved - must be zero */
#define NS_KEY_NAME_TYPE	0x0300	/* these bits determine the type */
#define NS_KEY_NAME_USER	0x0000	/* key is assoc. with user */
#define NS_KEY_NAME_ENTITY	0x0200	/* key is assoc. with entity eg host */
#define NS_KEY_NAME_ZONE	0x0100	/* key is zone key */
#define NS_KEY_NAME_RESERVED	0x0300	/* reserved meaning */
#define NS_KEY_RESERVED8	0x0080	/* reserved - must be zero */
#define NS_KEY_RESERVED9	0x0040	/* reserved - must be zero */
#define NS_KEY_RESERVED10	0x0020	/* reserved - must be zero */
#define NS_KEY_RESERVED11	0x0010	/* reserved - must be zero */
#define NS_KEY_SIGNATORYMASK	0x000F	/* key can sign RR's of same name */

#define NS_KEY_RESERVED_BITMASK ( NS_KEY_RESERVED2 | \
				  NS_KEY_RESERVED4 | \
				  NS_KEY_RESERVED5 | \
				  NS_KEY_RESERVED8 | \
				  NS_KEY_RESERVED9 | \
				  NS_KEY_RESERVED10 | \
				  NS_KEY_RESERVED11 )

#define NS_KEY_RESERVED_BITMASK2 0xFFFF	/* no bits defined here */

/* The Algorithm field of the KEY and SIG RR's is an integer, {1..254} */
#define NS_ALG_MD5RSA		1       /* MD5 with RSA */
#define NS_ALG_DH		2       /* Diffie Hellman KEY */
#define NS_ALG_DSA		3       /* DSA KEY */
#define NS_ALG_DSS		NS_ALG_DSA
#define NS_ALG_EXPIRE_ONLY	253     /* No alg, no security */
#define NS_ALG_PRIVATE_OID	254     /* Key begins with OID giving alg */

/* Protocol values  */
/* value 0 is reserved */
#define NS_KEY_PROT_TLS		1
#define NS_KEY_PROT_EMAIL	2
#define NS_KEY_PROT_DNSSEC	3
#define NS_KEY_PROT_IPSEC	4
#define NS_KEY_PROT_ANY		255

/* Signatures */
#define NS_MD5RSA_MIN_BITS	512	/* Size of a mod or exp in bits */
#define NS_MD5RSA_MAX_BITS	2552
	/* Total of binary mod and exp */
#define NS_MD5RSA_MAX_BYTES	((NS_MD5RSA_MAX_BITS+7/8)*2+3)
	/* Max length of text sig block */
#define NS_MD5RSA_MAX_BASE64	(((NS_MD5RSA_MAX_BYTES+2)/3)*4)
#define NS_MD5RSA_MIN_SIZE	((NS_MD5RSA_MIN_BITS+7)/8)
#define NS_MD5RSA_MAX_SIZE	((NS_MD5RSA_MAX_BITS+7)/8)

#define NS_DSA_SIG_SIZE		41
#define NS_DSA_MIN_BITS		512
#define NS_DSA_MAX_BITS		1024
#define NS_DSA_MIN_BYTES	213
#define NS_DSA_MAX_BYTES	405

ISC_LANG_ENDDECLS

#endif /* DNS_KEYVALUES_H */
