/* Copyright (C) RSA Data Security, Inc. created 1993, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef DNSSAFE_AHCBCPAD_H
#define DNSSAFE_AHCBCPAD_H 1

#include "ahchencr.h"

typedef struct AHSecretCBCPad {
  AHChooseEncryptDecrypt chooseEncryptDecrypt;                 /* base class */

  unsigned int _inputRemainder;    /* Used for encrypt to compute pad length */
} AHSecretCBCPad;

AHSecretCBCPad *AHSecretCBCPadConstructor2 PROTO_LIST
  ((AHSecretCBCPad *, struct B_AlgorithmInfoType *, POINTER));

int AHSecretCBCPadEncryptInit PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, B_Key *, B_ALGORITHM_CHOOSER,
    A_SURRENDER_CTX *));
int AHSecretCBCPadEncryptUpdate PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *,
    unsigned int, unsigned char *, unsigned int, B_Algorithm *,
    A_SURRENDER_CTX *));
int AHSecretCBCPadEncryptFinal PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *,
    unsigned int, B_Algorithm *, A_SURRENDER_CTX *));
int AHSecretCBCPadDecryptFinal PROTO_LIST
  ((THIS_ENCRYPT_DECRYPT *, unsigned char *, unsigned int *,
    unsigned int, B_Algorithm *, A_SURRENDER_CTX *));

#endif /* DNSSAFE_AHCBCPAD_H */

