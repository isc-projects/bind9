
/*
 * Note that we do not do the usual #ifdef ... #endif protection since this
 * file is used as a template.
 */

typedef struct RBT_NODE *RBT_NODE_T;

RBT_NODE_T RBT_FIND(RBT_NODE_T, RBT_KEY_T);
void RBT_INSERT(RBT_NODE_T, RBT_NODE_T *);
void RBT_PRINT(RBT_NODE_T);
