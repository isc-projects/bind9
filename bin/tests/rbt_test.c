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
#include <unistd.h>

#include <isc/boolean.h>

#include <dns/rbt.h>
#include <dns/fixedname.h>

char *progname;
isc_mem_t *mctx;

#define DNSNAMELEN 255

static dns_name_t *
create_name(char *s) {
	int length;
	isc_result_t result;
	isc_buffer_t source, target;
	static dns_name_t *name;

	if (s == NULL || *s == '\0') {
		printf("missing name argument\n");
		return (NULL);
	}

	length = strlen(s);

	isc_buffer_init(&source, s, length, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, length);

	/*
	 * It isn't really necessary in this program to create individual
	 * memory spaces for each name structure and its associate character
	 * string.  It is done in this program to provide a relatively
	 * easy way to test the callback from dns_rbt_deletename that is
	 * supposed to free the data associated with a node.
	 *
	 * The buffer for the actual name will immediately follow the
	 * name structure.
	 */
	name = isc_mem_get(mctx, sizeof(*name) + DNSNAMELEN);
	if (name == NULL) {
		printf("out of memory!\n");
		return (NULL);
	}

	dns_name_init(name, NULL);
	isc_buffer_init(&target, name + 1, DNSNAMELEN, ISC_BUFFERTYPE_BINARY);

	result = dns_name_fromtext(name, &source, dns_rootname,
				   ISC_FALSE, &target);

	if (result != DNS_R_SUCCESS) {
		printf("dns_name_fromtext(%s) failed: %s\n",
		       s, dns_result_totext(result));
		return (NULL);
	}

	return (name);
}

static void
delete_name(void *data, void *arg) {
	dns_name_t *name;

	(void)arg;
	name = data;
	isc_mem_put(mctx, data, sizeof(dns_name_t) + DNSNAMELEN);
}

static void
print_name(dns_name_t *name) {
	isc_buffer_t target;
	char *buffer[256];

	isc_buffer_init(&target, buffer, sizeof(buffer), ISC_BUFFERTYPE_TEXT);

	/*
	 * ISC_FALSE means absolute names have the final dot added.
	 */
	dns_name_totext(name, ISC_FALSE, &target);

	printf("%.*s", (int)target.used, (char *)target.base);
}

static void
iterate(dns_rbt_t *rbt, isc_boolean_t forward) {
	dns_name_t *foundname, *origin;
	dns_rbtnodechain_t chain;
	dns_fixedname_t fixedfoundname, fixedorigin;
	dns_result_t result;
	dns_result_t (*move)(dns_rbtnodechain_t *chain, dns_name_t *name,
			     dns_name_t *origin);

	dns_rbtnodechain_init(&chain, mctx);

	dns_fixedname_init(&fixedfoundname);
	dns_fixedname_init(&fixedorigin);
	foundname = dns_fixedname_name(&fixedfoundname);
	origin    = dns_fixedname_name(&fixedorigin);

	if (forward) {
		printf("iterating forward\n" );
		move = dns_rbtnodechain_next;
		
		result = dns_rbtnodechain_first(&chain, rbt, foundname, origin);

	} else {
		printf("iterating backward\n" );
		move = dns_rbtnodechain_prev;

		result = dns_rbtnodechain_last(&chain, rbt, foundname, origin);

	}

	if (result != DNS_R_SUCCESS && result != DNS_R_NEWORIGIN)
		printf("start not found!\n");

	else {
		while (1) {
			if (result == DNS_R_NEWORIGIN) {
				printf("  new origin: ");
				print_name(origin);
				printf("\n");
			}

			if (result == DNS_R_SUCCESS ||
			    result == DNS_R_NEWORIGIN) {
				print_name(foundname);
				printf("\n");

			} else {
				if (result != DNS_R_NOMORE)
				       printf("UNEXEPCTED ITERATION ERROR: %s",
					      dns_result_totext(result));
				break;
			}

			result = move(&chain, foundname, origin);
		}
	}
}


#define CMDCHECK(s)	(strncasecmp(command, (s), length) == 0)
#define PRINTERR(r)	if (r != DNS_R_SUCCESS) \
				printf("... %s\n", dns_result_totext(r));

void
main (int argc, char **argv) {
	char *command, *arg, *whitespace, buffer[1024];
	dns_name_t *name, *foundname;
	dns_fixedname_t fixedname;
	dns_rbt_t *rbt;
	int length, ch;
	isc_boolean_t show_final_mem = ISC_FALSE;
	isc_result_t result;
	void *data;

	progname = strrchr(*argv, '/');
	if (progname != NULL)
		progname++;
	else
		progname = *argv;

	while ((ch = getopt(argc, argv, "m")) != -1) {
		switch (ch) {
		case 'm':
			show_final_mem = ISC_TRUE;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1) {
		printf("Usage: %s [-m]\n", progname);
		exit(1);
	}

	setbuf(stdout, NULL);

	result = isc_mem_create(0, 0, &mctx);
	if (result != ISC_R_SUCCESS) {
		printf("isc_mem_create: %s: exiting\n",
		       dns_result_totext(result));
		exit(1);
	}

	result = dns_rbt_create(mctx, delete_name, NULL, &rbt);
	if (result != DNS_R_SUCCESS) {
		printf("dns_rbt_create: %s: exiting\n",
		       dns_result_totext(result));
		exit(1);
	}

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
				name = create_name(arg);
				if (name != NULL) {
					printf("adding name %s\n", arg);
					result = dns_rbt_addname(rbt,
								 name, name);
					PRINTERR(result);
				}

			} else if (CMDCHECK("delete")) {
				name = create_name(arg);
				if (name != NULL) {
					printf("deleting name %s\n", arg);
					result = dns_rbt_deletename(rbt, name,
								    ISC_FALSE);
					PRINTERR(result);
					delete_name(name, NULL);
				}

			} else if (CMDCHECK("nuke")) {
				name = create_name(arg);
				if (name != NULL) {
					printf("deleting name %s\n", arg);
					result = dns_rbt_deletename(rbt, name,
								    ISC_TRUE);
					PRINTERR(result);
					delete_name(name, NULL);
				}

			} else if (CMDCHECK("search")) {
				name = create_name(arg);
				if (name != NULL) {
					printf("searching for name %s ... ",
					       arg);

					dns_fixedname_init(&fixedname);
					foundname =
						dns_fixedname_name(&fixedname);
					data = NULL;

					result = dns_rbt_findname(rbt, name,
								  foundname,
								  &data);
					switch (result) {
					case DNS_R_SUCCESS:
						printf("found exact: ");
						print_name(data);
						putchar('\n');
						break;
					case DNS_R_PARTIALMATCH:
						printf("found parent: ");
						print_name(data);
						printf("\n\t(foundname: ");
						print_name(foundname);
						printf(")\n");

						break;
					case DNS_R_NOTFOUND:
						printf("NOT FOUND!\n");
						break;
					case DNS_R_NOMEMORY:
						printf("OUT OF MEMORY!\n");
						break;
					default:
						printf("UNEXPECTED RESULT\n");
					}

					delete_name(name, NULL);
				}

			} else if (CMDCHECK("forward")) {
				iterate(rbt, ISC_TRUE);

			} else if (CMDCHECK("backward")) {
				iterate(rbt, ISC_FALSE);

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
				       "s(earch) NAME, p(rint), or q(uit)\n");

			}
		}
			
	}

	dns_rbt_destroy(&rbt);

	if (show_final_mem)
		isc_mem_stats(mctx, stderr);

	exit(0);
}
