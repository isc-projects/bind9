/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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
#include <fcntl.h>
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

static void	t2(void);

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
dh(char *name1, int id1, char *name2, int id2, isc_mem_t *mctx,
   dst_result_t exp_result, int *nfails, int *nprobs)
{
	dst_key_t	*key1, *key2;
	dst_result_t	ret;
	int		rval;
	char		current[PATH_MAX + 1];
	char		tmp[PATH_MAX + 1];
	char		*p;
	int		alg = DST_ALG_DH;
	int		type = DST_TYPE_PUBLIC|DST_TYPE_PRIVATE;
	unsigned char	array1[1024], array2[1024];
	isc_buffer_t	b1, b2;
	isc_region_t	r1, r2;

	exp_result = exp_result; /* unused */

	p = getcwd(current, PATH_MAX);;
	if (p == NULL) {
		t_info("getcwd failed %d\n", errno);
		++*nprobs;
		return;
	}

	ret = dst_key_fromfile(name1, id1, alg, type, mctx, &key1);
	if (ret != ISC_R_SUCCESS) {
		t_info("dst_key_fromfile(%d) returned: %s\n",
		       alg, dst_result_totext(ret));
		++*nfails;
		return;
	}

	ret = dst_key_fromfile(name2, id2, alg, type, mctx, &key2);
	if (ret != ISC_R_SUCCESS) {
		t_info("dst_key_fromfile(%d) returned: %s\n",
		       alg, dst_result_totext(ret));
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

	ret = dst_key_tofile(key1, type);
	if (ret != 0) {
		t_info("dst_key_tofile(%d) returned: %s\n",
		       alg, dst_result_totext(ret));
		(void) chdir(current);
		++*nfails;
		return;
	}

	ret = dst_key_tofile(key2, type);
	if (ret != 0) {
		t_info("dst_key_tofile(%d) returned: %s\n",
		       alg, dst_result_totext(ret));
		(void) chdir(current);
		++*nfails;
		return;
	}

	if (chdir(current)) {
		t_info("chdir failed %d\n", errno);
		++*nprobs;
		return;
	}

	cleandir(tmp);

	isc_buffer_init(&b1, array1, sizeof(array1), ISC_BUFFERTYPE_BINARY);
	ret = dst_computesecret(key1, key2, &b1);
	if (ret != 0) {
		t_info("dst_computesecret() returned: %s\n",
		       dst_result_totext(ret));
		++*nfails;
		return;
	}

	isc_buffer_init(&b2, array2, sizeof(array2), ISC_BUFFERTYPE_BINARY);
	ret = dst_computesecret(key2, key1, &b2);
	if (ret != 0) {
		t_info("dst_computesecret() returned: %s\n",
		       dst_result_totext(ret));
		++*nfails;
		return;
	}

	isc_buffer_used(&b1, &r1);
	isc_buffer_used(&b2, &r2);
	if (r1.length != r2.length || memcmp(r1.base, r2.base, r1.length) != 0)
	{
		t_info("computed secrets don't match\n");
		++*nfails;
		return;
	}

	dst_key_free(key1);
	dst_key_free(key2);
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
	if (ret != ISC_R_SUCCESS) {
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

	if (dst_key_alg(key) != DST_ALG_DH)
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
generate(int alg, isc_mem_t *mctx, int size, int *nfails) {
	dst_result_t ret;
	dst_key_t *key;

	ret = dst_key_generate("test.", alg, size, 0, 0, 0, mctx, &key);
	if (ret != ISC_R_SUCCESS) {
		t_info("dst_key_generate(%d) returned: %s\n", alg, dst_result_totext(ret));
		++*nfails;
		return;
	}

	if (alg != DST_ALG_DH)
		use(key, ISC_R_SUCCESS, nfails);
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
	ret = dst_random_get(sizeof(data1), &databuf1);
	if (ret != ISC_R_SUCCESS) {
		t_info("random() returned: %s\n", dst_result_totext(ret));
		++*nfails;
		return;
	}

	isc_buffer_init(&databuf2, data2, sizeof(data2), ISC_BUFFERTYPE_BINARY);
	ret = dst_random_get(sizeof(data2), &databuf2);
	if (ret != ISC_R_SUCCESS) {
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
		"compute Diffie-Hellman shared secrets, "
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
			mctx, ISC_R_SUCCESS, &nfails, &nprobs);
	io("test.", 54622, DST_ALG_RSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC,
			mctx, ISC_R_SUCCESS, &nfails, &nprobs);

	io("test.", 0, DST_ALG_DSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC,
			mctx, DST_R_NULLKEY, &nfails, &nprobs);
	io("test.", 0, DST_ALG_RSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC,
			mctx, DST_R_NULLKEY, &nfails, &nprobs);

	dh("dh.", 18088, "dh.", 48443, mctx, ISC_R_SUCCESS, &nfails, &nprobs);

	t_info("testing use of generated keys\n");
	generate(DST_ALG_RSA, mctx, 512, &nfails);
	generate(DST_ALG_DSA, mctx, 512, &nfails);
	generate(DST_ALG_DH, mctx, 512, &nfails);
	generate(DST_ALG_DH, mctx, 768, &nfails); /* this one uses a constant */
	generate(DST_ALG_HMACMD5, mctx, 512, &nfails);

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

#define	T_SIGMAX	512

#undef	NEWSIG	/* define NEWSIG to generate the original signature file */

#ifdef	NEWSIG

/* write a sig in buf to file at path */
static int
sig_tofile(char *path, isc_buffer_t *buf) {
	int		rval;
	int		fd;
	int		len;
	int		nprobs;
	int		cnt;
	unsigned char	c;
	unsigned char	val;

	cnt = 0;
	nprobs = 0;
	len = buf->used - buf->current;

	t_info("buf: current %d used %d len %d\n", buf->current, buf->used, len);

	fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, S_IRWXU|S_IRWXO|S_IRWXG);
	if (fd < 0) {
		t_info("open %s failed %d\n", path, errno);
		return(1);
	}

	while (len) {
		c = (unsigned char) isc_buffer_getuint8(buf);
		val = ((c >> 4 ) & 0x0f);
		if ((0 <= val) && (val <= 9))
			val = '0' + val;
		else
			val = 'A' + val - 10;
		rval = write(fd, &val, 1);
		if (rval != 1) {
			++nprobs;
			t_info("write failed %d %d\n", rval, errno);
			break;
		}
		val = (c & 0x0f);
		if ((0 <= val) && (val <= 9))
			val = '0' + val;
		else
			val = 'A' + val - 10;
		rval = write(fd, &val, 1);
		if (rval != 1) {
			++nprobs;
			t_info("write failed %d %d\n", rval, errno);
			break;
		}
		--len;
		++cnt;
		if ((cnt % 16) == 0) {
			val = '\n';
			rval = write(fd, &val, 1);
			if (rval != 1) {
				++nprobs;
				t_info("write failed %d %d\n", rval, errno);
				break;
			}
		}
	}
	val = '\n';
	rval = write(fd, &val, 1);
	if (rval != 1) {
		++nprobs;
		t_info("write failed %d %d\n", rval, errno);
	}
	(void) close(fd);
	return(nprobs);
}

#endif	/* NEWSIG */

/* read sig in file at path to buf */
static int
sig_fromfile(char *path, isc_buffer_t *iscbuf) {
	int		rval;
	int		len;
	int		fd;
	unsigned char	val;
	struct stat	sb;
	char		*p;
	char		*buf;

	rval = stat(path, &sb);
	if (rval != 0) {
		t_info("stat %s failed, errno == %d\n", path, errno);
		return(1);
	}

	buf = (char *) malloc((sb.st_size + 1) * sizeof(unsigned char));
	if (buf == NULL) {
		t_info("malloc failed, errno == %d\n", errno);
		return(1);
	}
	
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		t_info("open failed, errno == %d\n", errno);
		(void) free(buf);
		return(1);
	}

	len = sb.st_size;
	p = buf;
	while (len) {
		rval = read(fd, p, len);
		if (rval > 0) {
			len -= rval;
			p += rval;
		}
		else {
			t_info("read failed %d, errno == %d\n", rval, errno);
			(void) free(buf);
			(void) close(fd);
			return(1);
		}
	}
	close(fd);

	p = buf;
	len = sb.st_size;
	while(len) {
		if (*p == '\n') {
			++p;
			--len;
			continue;
		}
		if (('0' <= *p) && (*p <= '9'))
			val = *p - '0';
		else
			val = *p - 'A' + 10;
		++p;
		val <<= 4;
		--len;
		if (('0' <= *p) && (*p <= '9'))
			val |= (*p - '0');
		else
			val |= (*p - 'A' + 10);
		++p;
		--len;
		isc_buffer_putuint8(iscbuf, val);
	}
	(void) free(buf);
	return(0);
}


static void
t2_sigchk(char *datapath, char *sigpath, char *keyname,
		int id, int alg, int type,
		isc_mem_t *mctx, char *expected_result,
		int *nfails, int *nprobs) {

	int		rval;
	int		len;
	int		fd;
	int		exp_res;
	dst_key_t	*key;
	unsigned char	sig[T_SIGMAX];
	unsigned char	*p;
	unsigned char	*data;
	struct stat	sb;
	isc_result_t	isc_result;
	isc_buffer_t	databuf;
	isc_buffer_t	sigbuf;
	isc_region_t	datareg;
	isc_region_t	sigreg;

	/* read data from file in a form usable by dst_verify */
	rval = stat(datapath, &sb);
	if (rval != 0) {
		t_info("t2_sigchk: stat (%s) failed %d\n", datapath, errno);
		++*nprobs;
		return;
	}

	data = (unsigned char *) malloc(sb.st_size * sizeof(char));
	if (data == NULL) {
		t_info("t2_sigchk: malloc failed %d\n", errno);
		++*nprobs;
		return;
	}

	fd = open(datapath, O_RDONLY);
	if (fd < 0) {
		t_info("t2_sigchk: open failed %d\n", errno);
		(void) free(data);
		++*nprobs;
		return;
	}

	p = data;
	len = sb.st_size;
	do {
		rval = read(fd, p, len);
		if (rval > 0) {
			len -= rval;
			p += rval;
		}
	} while (len);
	(void) close(fd);

	/* read key from file in a form usable by dst_verify */
	isc_result = dst_key_fromfile(keyname, id, alg, type, mctx, &key);
	if (isc_result != ISC_R_SUCCESS) {
		t_info("dst_key_fromfile failed %s\n",
			isc_result_totext(isc_result));
		(void) free(data);
		++*nprobs;
		return;
	}

	isc_buffer_init(&databuf, data, sb.st_size, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&databuf, sb.st_size);
	isc_buffer_used(&databuf, &datareg);

#ifdef	NEWSIG

	/*
	 * if we're generating a signature for the first time,
	 * sign the data and save the signature to a file
	 */

	memset(sig, 0, sizeof(sig));
	isc_buffer_init(&sigbuf, sig, sizeof(sig), ISC_BUFFERTYPE_BINARY);

	isc_result = dst_sign(DST_SIGMODE_ALL, key, NULL, &datareg, &sigbuf);
	if (isc_result != ISC_R_SUCCESS) {
		t_info("dst_sign(%d) failed %s\n", dst_result_totext(isc_result));
		(void) free(data);
		(void) dst_key_free(key);
		++*nprobs;
		return;
	}

	rval = sig_tofile(sigpath, &sigbuf);
	if (rval != 0) {
		t_info("sig_tofile failed\n");
		++*nprobs;
		(void) free(data);
		(void) dst_key_free(key);
		return;
	}

#endif	/* NEWSIG */

	memset(sig, 0, sizeof(sig));
	isc_buffer_init(&sigbuf, sig, sizeof(sig), ISC_BUFFERTYPE_BINARY);

	/* read precomputed signature from file in a form usable by dst_verify */
	rval = sig_fromfile(sigpath, &sigbuf);
	if (rval != 0) {
		t_info("sig_fromfile failed\n");
		(void) free(data);
		(void) dst_key_free(key);
		++*nprobs;
		return;
	}

	/* verify that the key signed the data */
	isc_buffer_remaining(&sigbuf, &sigreg);

	exp_res = 0;
	if (strstr(expected_result, "!"))
		exp_res = 1;

	isc_result = dst_verify(DST_SIGMODE_ALL, key, NULL, &datareg, &sigreg);
	if (	((exp_res == 0) && (isc_result != ISC_R_SUCCESS))	||
		((exp_res != 0) && (isc_result == ISC_R_SUCCESS)))	{

		t_info("dst_verify returned %s, expected %s\n",
			isc_result_totext(isc_result),
			expected_result);
		++*nfails;
	}

	(void) free(data);
	(void) dst_key_free(key);
	return;
}

/*
 * the astute observer will note that t1() signs then verifies data
 * during the test but that t2() verifies data that has been
 * signed at some earlier time, possibly with an entire different
 * version or implementation of the DSA and RSA algorithms
 */

static char	*a2 =
		"the dst module provides the capability to "
		"verify data signed with the RSA and DSA algorithms";

/* av ==  datafile, sigpath, keyname, keyid, alg, exp_result */
static int
t2_vfy(char **av) {
	char		*datapath;
	char		*sigpath;
	char		*keyname;
	char		*key;
	int		keyid;
	char		*alg;
	int		algid;
	char		*exp_result;
	int		nfails;
	int		nprobs;
	isc_mem_t	*mctx;
	isc_result_t	isc_result;
	int		result;

	datapath	= *av++;
	sigpath		= *av++;
	keyname		= *av++;
	key		= *av++;
	keyid		= atoi(key);
	alg		= *av++;
	exp_result	= *av++;
	nfails		= 0;
	nprobs		= 0;

	if (! strcasecmp(alg, "DST_ALG_DSA"))
		algid = DST_ALG_DSA;
	else if (! strcasecmp(alg, "DST_ALG_RSA"))
		algid = DST_ALG_RSA;
	else {
		t_info("Unknown algorithm %s\n", alg);
		return(T_UNRESOLVED);
	}

	mctx = NULL;
	isc_result = isc_mem_create(0, 0, &mctx);
	if (isc_result != ISC_R_SUCCESS) {
		t_info("isc_mem_create failed %d\n", isc_result_totext(isc_result));
		return(T_UNRESOLVED);
	}

	t_info("testing %s, %s, %s, %s, %s, %s\n",
			datapath, sigpath, keyname, key, alg, exp_result);
	t2_sigchk(datapath, sigpath, keyname, keyid,
			algid, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC,
			mctx, exp_result,
			&nfails, &nprobs);

	isc_mem_destroy(&mctx);

	result = T_UNRESOLVED;
	if (nfails)
		result = T_FAIL;
	else if ((nfails == 0) && (nprobs == 0))
		result = T_PASS;
	return(result);

}

static void
t2() {
	int	result;
	t_assert("dst", 2, T_REQUIRED, a2);
	result = t_eval("dst_2_data", t2_vfy, 6);
	t_result(result);
}

testspec_t	T_testlist[] = {
	{	t1,	"basic dst module verification"	},
	{	t2,	"signature ineffability"	},
	{	NULL,	NULL				}
};

