/* Copyright (C) RSA Data Security, Inc. created 1993, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef DNSSAFE_AHRSAEPU_H
#define DNSSAFE_AHRSAEPU_H 1

#include "ahrsaenc.h"

/* structure is identical to base class, so just re-typedef. */
typedef AH_RSAEncryption AH_RSAEncryptionPublic;

AH_RSAEncryptionPublic *AH_RSAEncrypPublicConstructor PROTO_LIST
  ((AH_RSAEncryptionPublic *));

#endif /* DNSSAFE_AHRSAEPU_H */

