
#ifndef ISC_RESULT_H
#define ISC_RESULT_H 1

typedef unsigned int isc_result;

#define ISC_R_SUCCESS			0
#define ISC_R_NOMEMORY			1
#define ISC_R_UNEXPECTED		0xFFFFFFFFL

#define isc_result_totext		__isc_result_totext

char *					isc_result_totext(isc_result);

#endif /* ISC_RESULT_H */
