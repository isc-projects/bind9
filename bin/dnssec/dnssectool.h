/*
 * Copyright (C) 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#ifndef DNSSECTOOL_H
#define DNSSECTOOL_H 1

void
fatal(const char *format, ...);

void
check_result(isc_result_t result, const char *message);

void
vbprintf(int level, const char *fmt, ...);

char *
nametostr(dns_name_t *name);

char *
typetostr(const dns_rdatatype_t type);

char *
algtostr(const dns_secalg_t alg);

void
setup_logging(int verbose, isc_mem_t *mctx, isc_log_t **logp);

void
setup_entropy(isc_mem_t *mctx, const char *randomfile, isc_entropy_t **ectx);

void
cleanup_entropy(isc_entropy_t **ectx);

#endif /* DNSSEC_DNSSECTOOL_H */
