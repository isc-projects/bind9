/* Copyright (C) RSA Data Security, Inc. created 1990, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef DNSSAFE_ALGOBJ_H
#define DNSSAFE_ALGOBJ_H 1

#define THE_ALG_WRAP ((AlgorithmWrap *)algorithmObject)

typedef struct AlgorithmWrap {
  B_Algorithm algorithm;
  char *typeTag;
  struct AlgorithmWrap *selfCheck;
} AlgorithmWrap;

int AlgorithmWrapCheck PROTO_LIST ((AlgorithmWrap *));
int RandomAlgorithmCheck PROTO_LIST ((B_ALGORITHM_OBJ));

#endif /* DNSSAFE_ALGOBJ_H */
