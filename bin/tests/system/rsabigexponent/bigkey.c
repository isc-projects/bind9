/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */


#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/region.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/util.h>

#define DST_KEY_INTERNAL

#include <dns/dnssec.h>
#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/log.h>
#include <dns/name.h>
#include <dns/rdataclass.h>
#include <dns/result.h>
#include <dns/secalg.h>

#include <dst/dst.h>
#include <dst/result.h>

/*
 * Use a fixed key file pair if compiled without OpenSSL.
 */

int
main(int argc, char **argv) {
	FILE *fp;

	UNUSED(argc);
	UNUSED(argv);

	fp = fopen("Kexample.+005+10264.private", "w");
	if (fp == NULL) {
		perror("fopen(Kexample.+005+10264.private)");
		exit(1);
	}

	fputs("Private-key-format: v1.3\n", fp);
	fputs("Algorithm: 5 (RSASHA1)\n", fp);
	fputs("Modulus: yhNbLRPA7VpLCXcgMvBwsfe7taVaTvLPY3AI+YolKwqD6"
	      "/3nLlCcz4kBOTOkQBf9bmO98WnKuOWoxuEOgudoDvQOzXNl9RJtt61"
	      "IRMscAlsVtTIfAjPLhcGy32l2s5VYWWVXx/qkcf+i/JC38YXIuVdiA"
	      "MtbgQV40ffM4lAbZ7M=\n", fp);
	fputs("PublicExponent: AQAAAAAAAQ==\n", fp);
	fputs("PrivateExponent: gfXvioazoFIJp3/H2kJncrRZaqjIf9+21CL1i"
	      "XecBOof03er8ym5AKopZQM8ie+qxvhDkIJ8YDrB7UbDxmFpPceHWYM"
	      "X0vDWQCIiEiKzRfCsBOjgJu6HS15G/oZDqDwKat+yegtzxhg48BCPq"
	      "zfHLXXUvBTA/HK/u8L1LwggqHk=\n", fp);
	fputs("Prime1: 7xAPHsNnS0w7CoEnIQiu+SrmHsy86HKJOEm9FiQybRVCwf"
	      "h4ZRQl+Z9mUbb9skjPvkM6ZeuzXTFkOjdck2y1NQ==\n", fp);
	fputs("Prime2: 2GRzzqyRR2gfITPug8Rddxt647/2DrAuKricX/AXyGcuHM"
	      "vTZ+v+mfgJn6TFqSn4SBF2zHJ876lWbQ+12aNORw==\n", fp);
	fputs("Exponent1: PnGTwxiT59N/Rq/FSAwcwoAudiF/X3iK0X09j9Dl8cY"
	      "DYAJ0bhB9es1LIaSsgLSER2b1kHbCp+FQXGVHJeZ07Q==\n", fp);
	fputs("Exponent2: Ui+zxA/zbnUSYnz+wdbrfBD2aTeKytZG4ASI3oPDZag"
	      "V9YC0eZRPjI82KQcFXoj1b/fV/HzT9/9rhU4mvCGjLw==\n", fp);
	fputs("Coefficient: sdCL6AdOaCr9c+RO8NCA492MOT9w7K9d/HauC+fif"
	      "2iWN36dA+BCKaeldS/+6ZTnV2ZVyVFQTeLJM8hplxDBwQ==\n", fp);

	if (fclose(fp) != 0) {
		perror("fclose(Kexample.+005+10264.private)");
		exit(1);
	}

	fp = fopen("Kexample.+005+10264.key", "w");
	if (fp == NULL) {
		perror("fopen(Kexample.+005+10264.key)");
		exit(1);
	}

	fputs("; This is a zone-signing key, keyid 10264, for example.\n", fp);
	fputs("example. IN DNSKEY 256 3 5 BwEAAAAAAAHKE1stE8DtWksJdyA"
	      "y8HCx97u1pVpO8s9jcAj5iiUrCoPr /ecuUJzPiQE5M6RAF/1uY73x"
	      "acq45ajG4Q6C52gO9A7Nc2X1Em23rUhE yxwCWxW1Mh8CM8uFwbLfaX"
	      "azlVhZZVfH+qRx/6L8kLfxhci5V2IAy1uB BXjR98ziUBtnsw==\n", fp);

	if (fclose(fp) != 0) {
		perror("close(Kexample.+005+10264.key)");
		exit(1);
	}

	return(0);
}

/*! \file */
