/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Hazard Pointer implementation.
 *
 * This work is based on C++ code available from:
 * https://github.com/pramalhe/ConcurrencyFreaks/
 *
 * Copyright (c) 2014-2016, Pedro Ramalhete, Andreia Correia
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Concurrency Freaks nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER>
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>

#include <isc/align.h>
#include <isc/atomic.h>
#include <isc/hp.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/os.h>
#include <isc/string.h>
#include <isc/thread.h>
#include <isc/util.h>

static int isc__hp_max_threads = 1;

typedef struct retirelist {
	int size;
	uintptr_t *list;
} retirelist_t;

typedef atomic_uintptr_t isc_hp_uintptr_t;

struct isc_hp {
	int max_hps;
	int max_retired;
	isc_mem_t *mctx;
	isc_hp_deletefunc_t *deletefunc;
	isc_hp_uintptr_t **hp;
	retirelist_t **rl;
};

static inline int
tid(void) {
	return (isc_tid_v);
}

void
isc_hp_init(int max_threads) {
	REQUIRE(max_threads > 0);

	if (isc__hp_max_threads > max_threads) {
		return;
	}

	isc__hp_max_threads = max_threads;
}

isc_hp_t *
isc_hp_new(isc_mem_t *mctx, size_t max_hps, isc_hp_deletefunc_t *deletefunc) {
	isc_hp_t *hp = isc_mem_get(mctx, sizeof(*hp));

	REQUIRE(isc__hp_max_threads > 0);
	REQUIRE(max_hps > 0);

	*hp = (isc_hp_t){
		.max_hps = max_hps,
		.max_retired = isc__hp_max_threads * max_hps,
		.deletefunc = deletefunc,
	};

	isc_mem_attach(mctx, &hp->mctx);

	hp->hp = isc_mem_get(mctx, isc__hp_max_threads * sizeof(hp->hp[0]));
	for (int i = 0; i < isc__hp_max_threads; i++) {
		isc_hp_uintptr_t *hps;

		hps = isc_mem_get_aligned(mctx, hp->max_hps * sizeof(*hps),
					  isc_os_cacheline());
		for (int j = 0; j < hp->max_hps; j++) {
			atomic_init(&hps[j], 0);
		}

		hp->hp[i] = hps;
	}

	hp->rl = isc_mem_get(mctx, isc__hp_max_threads * sizeof(hp->rl[0]));

	for (int i = 0; i < isc__hp_max_threads; i++) {
		retirelist_t *rl;

		rl = isc_mem_get_aligned(mctx, sizeof(*rl), isc_os_cacheline());
		rl->size = 0;
		rl->list = isc_mem_get(hp->mctx,
				       hp->max_retired * sizeof(uintptr_t));
		memset(rl->list, 0, hp->max_retired * sizeof(uintptr_t));

		hp->rl[i] = rl;
	}

	return (hp);
}

void
isc_hp_destroy(isc_hp_t *hp) {
	for (int i = 0; i < isc__hp_max_threads; i++) {
		retirelist_t *rl = hp->rl[i];

		for (int j = 0; j < rl->size; j++) {
			void *data = (void *)rl->list[j];
			hp->deletefunc(data);
		}
		isc_mem_put(hp->mctx, rl->list,
			    hp->max_retired * sizeof(uintptr_t));
		isc_mem_put_aligned(hp->mctx, rl, sizeof(*rl),
				    isc_os_cacheline());
	}
	for (int i = 0; i < isc__hp_max_threads; i++) {
		isc_hp_uintptr_t *hps = hp->hp[i];
		isc_mem_put_aligned(hp->mctx, hps, hp->max_hps * sizeof(*hps),
				    isc_os_cacheline());
	}
	isc_mem_put(hp->mctx, hp->hp, isc__hp_max_threads * sizeof(hp->hp[0]));
	isc_mem_put(hp->mctx, hp->rl, isc__hp_max_threads * sizeof(hp->rl[0]));

	isc_mem_putanddetach(&hp->mctx, hp, sizeof(*hp));
}

void
isc_hp_clear(isc_hp_t *hp) {
	for (int i = 0; i < hp->max_hps; i++) {
		atomic_store_release(&hp->hp[tid()][i], 0);
	}
}

void
isc_hp_clear_one(isc_hp_t *hp, int ihp) {
	atomic_store_release(&hp->hp[tid()][ihp], 0);
}

uintptr_t
isc_hp_protect(isc_hp_t *hp, int ihp, atomic_uintptr_t *atom) {
	uintptr_t n = 0;
	uintptr_t ret;
	while ((ret = atomic_load(atom)) != n) {
		atomic_store(&hp->hp[tid()][ihp], ret);
		n = ret;
	}
	return (ret);
}

uintptr_t
isc_hp_protect_ptr(isc_hp_t *hp, int ihp, atomic_uintptr_t ptr) {
	atomic_store(&hp->hp[tid()][ihp], atomic_load(&ptr));
	return (atomic_load(&ptr));
}

uintptr_t
isc_hp_protect_release(isc_hp_t *hp, int ihp, atomic_uintptr_t ptr) {
	atomic_store_release(&hp->hp[tid()][ihp], atomic_load(&ptr));
	return (atomic_load(&ptr));
}

void
isc_hp_retire(isc_hp_t *hp, uintptr_t ptr) {
	retirelist_t *rl = hp->rl[tid()];
	rl->list[rl->size++] = ptr;
	INSIST(rl->size < hp->max_retired);

	for (int iret = 0; iret < rl->size; iret++) {
		uintptr_t obj = rl->list[iret];
		bool can_delete = true;
		for (int itid = 0; itid < isc__hp_max_threads && can_delete;
		     itid++) {
			for (int ihp = hp->max_hps - 1; ihp >= 0; ihp--) {
				if (atomic_load(&hp->hp[itid][ihp]) == obj) {
					can_delete = false;
					break;
				}
			}
		}

		if (can_delete) {
			size_t bytes = (rl->size - iret) * sizeof(rl->list[0]);
			memmove(&rl->list[iret], &rl->list[iret + 1], bytes);
			rl->size--;
			hp->deletefunc((void *)obj);
		}
	}
}
