/*
 * Copyright (C) 2014-2015  Red Hat ; see COPYRIGHT for license
 */

#pragma once

#include "instance.h"
#include "util.h"

void
run_exclusive_enter(sample_instance_t *inst, isc_result_t *statep);

void
run_exclusive_exit(sample_instance_t *inst, isc_result_t state);
