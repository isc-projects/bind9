/*
 * Sync PTR records
 *
 * Copyright (C) 2014-2015  Red Hat ; see COPYRIGHT for license
 */

#pragma once

#include <isc/result.h>

#include <dns/diff.h>
#include <dns/name.h>
#include <dns/rdataset.h>

#include "instance.h"

isc_result_t
syncptrs(sample_instance_t *inst, dns_name_t *name, dns_rdataset_t *rdataset,
	 dns_diffop_t op);
