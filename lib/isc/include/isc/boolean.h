
#ifndef BOOLEAN_H
#define BOOLEAN_H 1

#ifndef SOLARIS

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

typedef enum { false=FALSE, true=TRUE } boolean_t;

#else

#define true B_TRUE
#define false B_FALSE

#endif

#endif /* BOOLEAN_H */
