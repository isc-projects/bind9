
/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

#include	<config.h>

#include	<ctype.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>

#include	<isc/boolean.h>

#include	<dns/rbt.h>
#include	<dns/fixedname.h>

#include	<tests/t_api.h>

char *progname;
isc_mem_t *T1_mctx;

#define DNSNAMELEN 255

char	*Tokens[T_MAXTOKS];

#ifdef	NEED_PRINT_DATA

static dns_result_t
print_data(void *data) {
	dns_result_t	dns_result;
	isc_buffer_t	target;
	char		*buffer[DNSNAMELEN];

	isc_buffer_init(&target, buffer, sizeof(buffer), ISC_BUFFERTYPE_TEXT);

	dns_result = dns_name_totext(data, ISC_FALSE, &target);
	if (dns_result != DNS_R_SUCCESS) {
		t_info("dns_name_totext failed %s\n",
				dns_result_totext(dns_result));
	}
	return(dns_result);
}

#endif	/* NEED_PRINT_DATA */

static int
create_name(char *s, isc_mem_t *mctx, dns_name_t **dns_name) {
	int		nfails;
	int		length;
	isc_result_t	result;
	isc_buffer_t	source;
	isc_buffer_t	target;

	nfails = 0;

	if (s && *s) {

		length = strlen(s);
	
		isc_buffer_init(&source, s, length, ISC_BUFFERTYPE_TEXT);
		isc_buffer_add(&source, length);
	
		/*
		 * The buffer for the actual name will immediately follow the
		 * name structure.
		 */
		*dns_name = isc_mem_get(mctx, sizeof(**dns_name) + DNSNAMELEN);
		if (*dns_name == NULL) {
			t_info("isc_mem_get failed\n");
			++nfails;
		}
	
		dns_name_init(*dns_name, NULL);
		isc_buffer_init(&target, *dns_name + 1, DNSNAMELEN,
					ISC_BUFFERTYPE_BINARY);
	
		result = dns_name_fromtext(*dns_name, &source, dns_rootname,
					   ISC_FALSE, &target);
	
		if (result != DNS_R_SUCCESS) {
			++nfails;
			t_info("dns_name_fromtext(%s) failed %s\n",
			       s, dns_result_totext(result));
		}
	}
	else {
		++nfails;
		t_info("create_name: empty name\n");
	}

	return(nfails);
}

static void
delete_name(void *data, void *arg) {
	dns_name_t *name;

	name = (dns_name_t *) data;
	isc_mem_put((isc_mem_t *) arg, data, sizeof(dns_name_t) + DNSNAMELEN);
}

#define	BUFLEN		1024

/* adapted from the original rbt_test.c */

static int
t1_add(char *name, dns_rbt_t *rbt, isc_mem_t *mctx, dns_result_t *dns_result) {

	int		nprobs;
	dns_name_t	*dns_name;

	nprobs = 0;
	if (name && dns_result) {
		*dns_result = create_name(name, mctx, &dns_name);
		if (*dns_result == DNS_R_SUCCESS) {
			*dns_result = dns_rbt_addname(rbt, dns_name, dns_name);
		}
		else {
			++nprobs;
		}
	}
	else {
		++nprobs;
	}
	return(nprobs);
}

static int
t1_delete(char *name, dns_rbt_t *rbt, isc_mem_t *mctx, dns_result_t *dns_result) {
	int		nprobs;
	dns_name_t	*dns_name;

	nprobs = 0;
	if (name && dns_result) {
		*dns_result = create_name(name, mctx, &dns_name);
		if (*dns_result == DNS_R_SUCCESS) {
			*dns_result = dns_rbt_deletename(rbt, dns_name, ISC_FALSE);
			delete_name(dns_name, mctx);
		}
		else {
			++nprobs;
		}
	}
	else {
		++nprobs;
	}
	return(nprobs);
}

static int
t1_search(char *name, dns_rbt_t *rbt, isc_mem_t *mctx, dns_result_t *dns_result) {

	int		nprobs;
	dns_name_t	*dns_searchname;
	dns_name_t	*dns_foundname;
	dns_fixedname_t	dns_fixedname;
	void		*data;

	nprobs = 0;
	if (name && dns_result) {
		*dns_result = create_name(name, mctx, &dns_searchname);
		if (*dns_result == DNS_R_SUCCESS) {
			dns_fixedname_init(&dns_fixedname);
			dns_foundname = dns_fixedname_name(&dns_fixedname);
			data = NULL;
			*dns_result = dns_rbt_findname(rbt, dns_searchname,
						dns_foundname, &data);
			delete_name(dns_searchname, mctx);
		}
		else {
			++nprobs;
		}
	}
	else {
		++nprobs;
	}
	return(nprobs);
}


static int
test_rbt_gen(char *filename, char *command, char *testname, dns_result_t exp_result) {
	int		rval;
	int		result;
	char		*p;
	dns_rbt_t	*rbt;
	isc_result_t	isc_result;
	dns_result_t	dns_result;
	FILE		*fp;

	result = T_UNRESOLVED;

	if (strcmp(command, "create") != 0)
		t_info("testing using name %s\n", testname);

	T1_mctx = NULL;
	isc_result = isc_mem_create(0, 0, &T1_mctx);
	if (isc_result != ISC_R_SUCCESS) {
		t_info("isc_mem_create: %s: exiting\n",
		       dns_result_totext(isc_result));
		return(T_UNRESOLVED);
	}

	/* initialize the database */
	fp = fopen(filename, "r");
	if (fp == NULL) {
		t_info("No such file %s\n", filename);
		return(T_UNRESOLVED);
	}

	rbt = NULL;
	dns_result = dns_rbt_create(T1_mctx, delete_name, T1_mctx, &rbt);
	if (dns_result != DNS_R_SUCCESS) {
		t_info("dns_rbt_create failed %s\n",
		       		dns_result_totext(dns_result));
		fclose(fp);
		return(T_UNRESOLVED);
	}

	/* load up the database */
	while ((p = t_fgetbs(fp)) != NULL) {

		/* skip any comment lines */
		if ((*p == '#') || (*p == '\0') || (*p == ' ')) {
			free(p);
			continue;
		}

		if (T_debug)
			t_info("adding name %s to the rbt\n", p);

		rval = t1_add(p, rbt, T1_mctx, &dns_result);
		if ((rval != 0) || (dns_result != DNS_R_SUCCESS)) {
			dns_rbt_destroy(&rbt);
			fclose(fp);
			return(T_UNRESOLVED);
		}
		(void) free(p);
	}
	fclose(fp);

		
	/* now try the database command */
	if (strcmp(command, "create") == 0) {
		dns_rbt_destroy(&rbt);
		return(T_PASS);
	}
	else if (strcmp(command, "add") == 0) {
		rval = t1_add(testname, rbt, T1_mctx, &dns_result);
		if (rval == 0) {
			if (dns_result == exp_result) {
				rval = t1_search(testname, rbt, T1_mctx, &dns_result);
				if (rval == 0) {
					if (dns_result == DNS_R_SUCCESS) {
						result = T_PASS;
					}
					else {
						t_info("dns_rbt_addname didn't "
							"add the name");
						result = T_FAIL;
					}
				}
			}
			else {
				t_info("add returned %s, expected %s\n",
					dns_result_totext(dns_result),
					dns_result_totext(exp_result));
				result = T_FAIL;
			}
		}
	}
	else if ((strcmp(command, "delete") == 0) ||
		(strcmp(command, "nuke") == 0)) {

		rval = t1_delete(testname, rbt, T1_mctx, &dns_result);
		if (rval == 0) {
			if (dns_result == exp_result) {
				rval = t1_search(testname, rbt, T1_mctx, &dns_result);
				if (rval == 0) {
					if (dns_result == DNS_R_SUCCESS) {
						t_info("dns_rbt_deletename didn't "
							"delete the name");
						result = T_FAIL;
					}
					else {
						result = T_PASS;
					}
				}
			}
			else {
				t_info("delete returned %s, expected %s\n",
					dns_result_totext(dns_result),
					dns_result_totext(exp_result));
				result = T_FAIL;
			}
		}
	}
	else if (strcmp(command, "search") == 0) {

		rval = t1_search(testname, rbt, T1_mctx, &dns_result);
		if (rval == 0) {
			if (dns_result == exp_result) {
				result = T_PASS;
			}
			else {
				t_info("find returned %s, expected %s\n",
					dns_result_totext(dns_result),
					dns_result_totext(exp_result));
				result = T_FAIL;
			}
		}
	}

	dns_rbt_destroy(&rbt);
	return(result);
}

static int
test_dns_rbt_x(char *filename) {

	FILE		*fp;
	char		*p;
	int		line;
	int		cnt;
	int		result;
	int		nfails;
	int		nprobs;

	nfails = 0;
	nprobs = 0;

	fp = fopen(filename, "r");
	if (fp != NULL) {
		line = 0;
		while ((p = t_fgetbs(fp)) != NULL) {

			++line;

			/* skip comment lines */
			if ((isspace(*p)) || (*p == '#'))
				continue;

			/* name of db file, command, testname, expected result */
			cnt = t_bustline(p, Tokens);
			if (cnt == 4) {
				result = test_rbt_gen(
						Tokens[0],
						Tokens[1],
						Tokens[2],
						t_dns_result_fromtext(Tokens[3]));
				if (result != T_PASS)
					++nfails;
			}
			else {
				t_info("bad format in %s at line %d\n",
						filename, line);
				++nprobs;
			}

			(void) free(p);
		}
		(void) fclose(fp);
	}
	else {
		t_info("Missing datafile %s\n", filename);
		++nprobs;
	}

	result = T_UNRESOLVED;
	if ((nfails == 0) && (nprobs == 0))
		result = T_PASS;
	else if (nfails)
		result = T_FAIL;

	return(result);
}


static char	*a1 =	"dns_rbt_create creates a rbt and returns DNS_R_SUCCESS "
			"on success";

static void
t1() {
	int	result;

	t_assert("dns_rbt_create", 1, T_REQUIRED, a1);
	result = test_dns_rbt_x("dns_rbt_create_1_data");
	t_result(result);
}

static char	*a2 =	"dns_rbt_addname adds a name to a database and returns "
			"DNS_R_SUCCESS on success";
static void
t2() {
	int	result;

	t_assert("dns_rbt_addname", 2, T_REQUIRED, a2);
	result = test_dns_rbt_x("dns_rbt_addname_1_data");
	t_result(result);
}

static char	*a3 =	"when name already exists, dns_rbt_addname() returns "
			"DNS_R_EXISTS";

static void
t3() {
	int	result;

	t_assert("dns_rbt_addname", 3, T_REQUIRED, a3);
	result = test_dns_rbt_x("dns_rbt_addname_2_data");
	t_result(result);
}

static char	*a4 =	"when name exists, dns_rbt_deletename() returns "
			"DNS_R_SUCCESS";

static void
t4() {
	int	result;

	t_assert("dns_rbt_deletename", 4, T_REQUIRED, a4);
	result = test_dns_rbt_x("dns_rbt_deletename_1_data");
	t_result(result);
}

static char	*a5 =	"when name does not exist, dns_rbt_deletename() returns "
			"DNS_R_NOTFOUND";
static void
t5() {
	int	result;

	t_assert("dns_rbt_deletename", 5, T_REQUIRED, a5);
	result = test_dns_rbt_x("dns_rbt_deletename_2_data");
	t_result(result);
}

static char	*a6 =	"when name exists and exactly matches the search name, "
			"dns_rbt_findname() returns DNS_R_SUCCESS";

static void
t6() {
	int	result;

	t_assert("dns_rbt_findname", 6, T_REQUIRED, a6);
	result = test_dns_rbt_x("dns_rbt_findname_1_data");
	t_result(result);
}

static char	*a7 =	"when a name does not exist, "
			"dns_rbt_findname returns DNS_R_NOTFOUND";

static void
t7() {
	int	result;

	t_assert("dns_rbt_findname", 7, T_REQUIRED, a7);
	result = test_dns_rbt_x("dns_rbt_findname_2_data");
	t_result(result);
}

static char	*a8 =	"when a superdomain is found with data matching name, "
			"dns_rbt_findname returns DNS_R_PARTIALMATCH";

static void
t8() {
	int	result;

	t_assert("dns_rbt_findname", 8, T_REQUIRED, a8);
	result = test_dns_rbt_x("dns_rbt_findname_3_data");
	t_result(result);
}

testspec_t	T_testlist[] = {
	{	t1,	"dns_rbt_create"	},
	{	t2,	"dns_rbt_addname 1"	},
	{	t3,	"dns_rbt_addname 2"	},
	{	t4,	"dns_rbt_deletename 1"	},
	{	t5,	"dns_rbt_deletename 2"	},
	{	t6,	"dns_rbt_findname 1"	},
	{	t7,	"dns_rbt_findname 2"	},
	{	t8,	"dns_rbt_findname 3"	},
	{	NULL,	NULL			}
};

