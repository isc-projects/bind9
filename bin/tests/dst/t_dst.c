/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <config.h>

#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <unistd.h>		/* XXX */

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/boolean.h>
#include <isc/region.h>
#include <isc/mem.h>

#include <dst/dst.h>
#include <dst/result.h>

#include <tests/t_api.h>

static void	t1(void);

/*
 * adapted from the original dst_test.c program
 */

static void
cleandir(char *path) {
	DIR		*dirp;
	struct dirent	*pe;
	char		fullname[PATH_MAX + 1];

	dirp = opendir(path);
	if (dirp == NULL) {
		t_info("opendir(%s) failed %d\n", path, opendir);
		return;
	}

	while ((pe = readdir(dirp)) != NULL) {
		if (! strcmp(pe->d_name, "."))
			continue;
		if (! strcmp(pe->d_name, ".."))
			continue;
		strcpy(fullname, path);
		strcat(fullname, "/");
		strcat(fullname, pe->d_name);
		if (remove(fullname)) {
			t_info("remove(%s) failed %d\n", fullname, errno);
		}
	}
	(void) closedir(dirp);
	if (rmdir(path)) {
		t_info("rmdir(%s) failed %d\n", path, errno);
	}
	return;
}


static void
use(dst_key_t *key, dst_result_t exp_result, int *nfails) {

	dst_result_t ret;
	char *data = "This is some data";
	unsigned char sig[512];
	isc_buffer_t databuf, sigbuf;
	isc_region_t datareg, sigreg;

	isc_buffer_init(&sigbuf, sig, sizeof(sig), ISC_BUFFERTYPE_BINARY);
	isc_buffer_init(&databuf, data, strlen(data), ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&databuf, strlen(data));
	isc_buffer_used(&databuf, &datareg);

	ret = dst_sign(DST_SIGMODE_ALL, key, NULL, &datareg, &sigbuf);
	if (ret != exp_result) {
		t_info("dst_sign(%d) returned (%s) expected (%s)\n",
				dst_key_alg(key), dst_result_totext(ret),
				dst_result_totext(exp_result));
		++*nfails;
		return;
	}


	isc_buffer_remaining(&sigbuf, &sigreg);
	ret = dst_verify(DST_SIGMODE_ALL, key, NULL, &datareg, &sigreg);
	if (ret != exp_result) {
		t_info("dst_verify(%d) returned (%s) expected (%s)\n",
				dst_key_alg(key), dst_result_totext(ret),
				dst_result_totext(exp_result));
		++*nfails;
	}
}

static void
io(char *name, int id, int alg, int type, isc_mem_t *mctx, dst_result_t exp_result,
		int *nfails, int *nprobs) {
	dst_key_t	*key;
	dst_result_t	ret;
	int		rval;
	char		current[PATH_MAX + 1];
	char		tmp[PATH_MAX + 1];
	char		*p;

	p = getcwd(current, PATH_MAX);;
	if (p == NULL) {
		t_info("getcwd failed %d\n", errno);
		++*nprobs;
		return;
	}

	ret = dst_key_fromfile(name, id, alg, type, mctx, &key);
	if (ret != DST_R_SUCCESS) {
		t_info("dst_key_fromfile(%d) returned: %s\n", alg, dst_result_totext(ret));
		++*nfails;
		return;
	}

	p = tmpnam(tmp);
	if (p == NULL) {
		t_info("tmpnam failed %d\n", errno);
		++*nprobs;
		return;
	}

	rval = mkdir(tmp, S_IRWXU | S_IRWXG );
	if (rval != 0) {
		t_info("mkdir failed %d\n", errno);
		++*nprobs;
		return;
	}

	if (chdir(tmp)) {
		t_info("chdir failed %d\n", errno);
		(void) rmdir(tmp);
		++*nprobs;
		return;
	}

	ret = dst_key_tofile(key, type);
	if (ret != 0) {
		t_info("dst_key_tofile(%d) returned: %s\n", alg, dst_result_totext(ret));
		(void) chdir(current);
		++*nfails;
		return;
	}

	use(key, exp_result, nfails);

	if (chdir(current)) {
		t_info("chdir failed %d\n", errno);
		++*nprobs;
		return;
	}

	cleandir(tmp);

	dst_key_free(key);
}

static void
generate(int alg, isc_mem_t *mctx, int *nfails) {
	dst_result_t ret;
	dst_key_t *key;

	ret = dst_key_generate("test.", alg, 512, 0, 0, 0, mctx, &key);
	if (ret != DST_R_SUCCESS) {
		t_info("dst_key_generate(%d) returned: %s\n", alg, dst_result_totext(ret));
		++*nfails;
		return;
	}

	use(key, DST_R_SUCCESS, nfails);
	dst_key_free(key);
}

#define	DBUFSIZ	25

static void
get_random(int *nfails) {
	unsigned char data1[DBUFSIZ];
	unsigned char data2[DBUFSIZ];
	isc_buffer_t databuf1;
	isc_buffer_t databuf2;
	dst_result_t ret;
	unsigned int i;

	isc_buffer_init(&databuf1, data1, sizeof(data1), ISC_BUFFERTYPE_BINARY);
	ret = dst_random(sizeof(data1), &databuf1);
	if (ret != DST_R_SUCCESS) {
		t_info("random() returned: %s\n", dst_result_totext(ret));
		++*nfails;
		return;
	}

	isc_buffer_init(&databuf2, data2, sizeof(data2), ISC_BUFFERTYPE_BINARY);
	ret = dst_random(sizeof(data2), &databuf2);
	if (ret != DST_R_SUCCESS) {
		t_info("random() returned: %s\n", dst_result_totext(ret));
		++*nfails;
		return;
	}

	/* weak test, but better than nought */
	if (memcmp(data1, data2, DBUFSIZ) == 0) {
		t_info("data not random\n");
		++*nfails;
	}

	if (T_debug) {
		for (i = 0; i < sizeof(data1); i++)
			t_info("data1[%d]: %02x ", i, data1[i]);
		for (i = 0; i < sizeof(data2); i++)
			t_info("data2[%d]: %02x ", i, data2[i]);
	}
}

static char	*a1 =
		"the dst module provides the capability to "
		"generate, store and retrieve public and private keys, "
		"sign and verify data using the RSA, DSA and MD5 algorithms, "
		"and generate random number sequences.";
static void
t1() {
	isc_mem_t	*mctx;
	int		nfails;
	int		nprobs;
	int		result;
	isc_result_t	isc_result;

	t_assert("dst", 1, T_REQUIRED, a1);

	nfails = 0;
	nprobs = 0;
	mctx = NULL;
	isc_result = isc_mem_create(0, 0, &mctx);
	if (isc_result != ISC_R_SUCCESS) {
		t_info("isc_mem_create failed %d\n", isc_result_totext(isc_result));
		t_result(T_UNRESOLVED);
		return;
	}

	t_info("testing use of stored keys\n");
	io("test.", 6204, DST_ALG_DSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC,
			mctx, DST_R_SUCCESS, &nfails, &nprobs);
	io("test.", 54622, DST_ALG_RSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC,
			mctx, DST_R_SUCCESS, &nfails, &nprobs);

	io("test.", 0, DST_ALG_DSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC,
			mctx, DST_R_NULLKEY, &nfails, &nprobs);
	io("test.", 0, DST_ALG_RSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC,
			mctx, DST_R_NULLKEY, &nfails, &nprobs);

	t_info("testing use of generated keys\n");
	generate(DST_ALG_RSA, mctx, &nfails);
	generate(DST_ALG_DSA, mctx, &nfails);
	generate(DST_ALG_HMAC_MD5, mctx, &nfails);

	t_info("testing random number sequence generation\n");
	get_random(&nfails);

	isc_mem_destroy(&mctx);

	result = T_UNRESOLVED;
	if ((nfails == 0) && (nprobs == 0))
		result = T_PASS;
	else if (nfails)
		result = T_FAIL;
	t_result(result);

}

testspec_t	T_testlist[] = {
	{	t1,	"basic dst module verification"	},
	{	NULL,	NULL			}
};

