/* Copyright (C) RSA Data Security, Inc. created 1990, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef DNSSAFE_KEYOBJ_H
#define DNSSAFE_KEYOBJ_H 1

typedef struct KeyWrap {
  B_Key key;
  char *typeTag;
  struct KeyWrap *selfCheck;
} KeyWrap;

int KeyWrapCheck PROTO_LIST ((KeyWrap *));

#endif /* DNSSAFE_KEYOBJ_H */
