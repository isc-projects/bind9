/*
 * @ISCCopyright@
 */

#ifndef ISC_REGION_H
#define ISC_REGION_H 1

typedef struct isc_region {
	unsigned char *	base;
	unsigned int	length;
} *isc_region_t;

typedef struct isc_textregion {
	char *		base;
	unsigned int	length;
} *isc_textregion_t;

/*
 * There are no methods which operate on regions.  The structure is not
 * opaque, and must be directly manipulated by applications.
 */

#endif /* ISC_REGION_H */
