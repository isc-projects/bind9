
/*
 * Note that we do not do the usual #ifdef ... #endif protection since this
 * file is used as a template.
 */

#include <isc/result.h>

typedef struct RBT_NODE *RBT_NODE_T;

RBT_LINKAGE isc_result_t RBT_INSERT(RBT_NODE_T, RBT_NODE_T *);
RBT_LINKAGE RBT_NODE_T RBT_SEARCH(RBT_NODE_T, RBT_KEY_T);
RBT_LINKAGE void RBT_PRINT(RBT_NODE_T);
