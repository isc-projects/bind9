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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <isc/boolean.h>
#include <isc/error.h>

#include <dns/rbt.h>

char *progname;

static dns_name_t *
create_name(char *s) {
	int length;
	isc_result_t result;
	isc_buffer_t source, target;
	static dns_name_t name;
	static char buffer[256];

	/*
	 * Note that this function uses static space for holding the
	 * returned name.  This is fine for this test program, but probably
	 * inadequate in most other programs that are not dealing with
	 * solely one name at a time.
	 */

	length = strlen(s);
	isc_buffer_init(&source, s, length, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, length);

	isc_buffer_init(&target, buffer, sizeof(buffer),
			ISC_BUFFERTYPE_BINARY);

	dns_name_init(&name, NULL);

	result = dns_name_fromtext(&name, &source, dns_rootname, 0,
				         &target);

	if (result != DNS_R_SUCCESS) {
		printf("dns_name_fromtext(%s) failed: %s\n",
		       s, dns_result_totext(result));
		return NULL;
	}

	return &name;
}

/*
 * Not currently useful.  Will be changed so create_name allocates memory
 * and this function cleans it up.
 */
static void
delete_name(void *data) {
	dns_name_t *name;

	name = data;
}

#define CMDCHECK(s)	(strncasecmp(command, (s), length) == 0)

void
main (int argc, char **argv) {
	char *command, *arg, *whitespace, buffer[1024];
	int length;
	dns_name_t *name;
	dns_rbt_t *rbt;
	dns_rbtnode_t *node;
	isc_result_t result;
	isc_mem_t *mctx;

	progname = strrchr(*argv, '/');
	if (progname != NULL)
		progname++;
	else
		progname = *argv;

	if (argc > 1) {
		printf("Usage: %s\n", progname);
		exit(1);
	}

	setbuf(stdout, NULL);

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	result = dns_rbt_create(mctx, delete_name, &rbt);
	if (result != DNS_R_SUCCESS)
		printf("dns_rbt_create: %s: exiting\n",
		       dns_result_totext(result));

	whitespace = " \t";

	while (fgets(buffer, sizeof(buffer), stdin) != NULL) {
		length = strlen(buffer);

		if (buffer[length - 1] != '\n') {
			printf("line to long (%d max), ignored\n",
			       sizeof(buffer) - 2);
			continue;
		}

		buffer[length - 1] = '\0';

		command = buffer + strspn(buffer, whitespace);
		arg = strpbrk(command, whitespace);
		if (arg != NULL) {
			*arg++ = '\0';
			arg += strspn(arg, whitespace);
		}

		length = strlen(command);
		if (*command != '\0') {
			if (CMDCHECK("add")) {
				if (arg != NULL && *arg != '\0') {
					name = create_name(arg);
					if (name != NULL) {
						printf("adding name %s\n",
						       arg);
						result = dns_rbt_addname(rbt,
								 name, name);
						if (result != DNS_R_SUCCESS)
							printf("... %s\n",
						    dns_result_totext(result));
					}
				} else
					printf("usage: add NAME\n");

			} else if (CMDCHECK("delete")) {
				if (arg != NULL && *arg != '\0') {
					name = create_name(arg);
					if (name != NULL) {
						printf("deleting name %s\n",
						       arg);
						result = dns_rbt_deletename
							    (rbt, name,
							     ISC_FALSE);
						if (result != DNS_R_SUCCESS)
							printf("... %s\n",
						    dns_result_totext(result));
					}
				} else
					printf("usage: delete NAME\n");

			} else if (CMDCHECK("nuke")) {
				if (arg != NULL && *arg != '\0') {
					name = create_name(arg);
					if (name != NULL) {
						printf("deleting name %s\n",
						       arg);
						result = dns_rbt_deletename
							    (rbt, name,
							     ISC_TRUE);
						if (result != DNS_R_SUCCESS)
							printf("... %s\n",
						    dns_result_totext(result));
					}
				} else
					printf("usage: delete NAME\n");

			} else if (CMDCHECK("search")) {
				if (arg != NULL && *arg != '\0') {
					name = create_name(arg);
					if (name != NULL) {
						printf("searching for "
						       "name %s ... ", arg);
						node = dns_rbt_findnode
							(rbt, name, NULL);
						if (node != NULL)
							printf("found it.\n");
						else
							printf("NOT FOUND!\n");
					}
				} else
					printf("usage: search NAME\n");


			} else if (CMDCHECK("print")) {
				if (arg == NULL || *arg == '\0')
					dns_rbt_printall(rbt);
				else
					printf("usage: print\n");

			} else if (CMDCHECK("quit")) {
				if (arg == NULL || *arg == '\0')
					break;
				else
					printf("usage: quit\n");
			} else {
				printf("a(dd) NAME, d(elete) NAME, "
				       "s(earch) NAME, print, or quit\n");

			}
		}
			
	}

	dns_rbt_destroy(&rbt);
	exit(0);
}
