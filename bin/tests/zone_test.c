#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <isc/error.h>
#include <isc/mem.h>
#include <isc/app.h>

#include <dns/db.h>
#include <dns/zone.h>
#include <dns/rdataclass.h>

static int debug = 0;
static int quiet = 0;
static int stats = 0;
static isc_mem_t *mctx = NULL;
dns_zone_t *zone = NULL;
isc_taskmgr_t *manager = NULL;
dns_zonetype_t zonetype = dns_zone_master;
isc_sockaddr_t addr;

#define ERRRET(result, function) \
	do { \
		if (result != DNS_R_SUCCESS) { \
			fprintf(stderr, "%s() returned %s\n", \
				function, dns_result_totext(result)); \
			return; \
		} \
	} while (0)

#define ERRCONT(result, function) \
		if (result != DNS_R_SUCCESS) { \
			fprintf(stderr, "%s() returned %s\n", \
				function, dns_result_totext(result)); \
			continue; \
		} else \
			(void)NULL

static void
usage() {
	fprintf(stderr,
		"usage: test_zone [-dqsSM] [-c class] [-f file] zone\n");
	exit(1);
}

static void
setup(char *zonename, char *filename, char *classname) {
	dns_result_t result;
	dns_rdataclass_t rdclass;
	isc_textregion_t region;

	if (debug)
		fprintf(stderr, "loading \"%s\" from \"%s\" class \"%s\"\n",
			zonename, filename, classname);
	result = dns_zone_create(&zone, mctx);
	ERRRET(result, "dns_zone_new");

	dns_zone_settype(zone, zonetype);

	result = dns_zone_setorigin(zone, zonename);
	ERRRET(result, "dns_zone_setorigin");

	result = dns_zone_setdbtype(zone, "rbt");
	ERRRET(result, "dns_zone_setdatabase");

	result = dns_zone_setdatabase(zone, filename);
	ERRRET(result, "dns_zone_setdatabase");

	region.base = classname;
	region.length = strlen(classname);
	result = dns_rdataclass_fromtext(&rdclass, &region); 
	ERRRET(result, "dns_rdataclass_fromtext");

	dns_zone_setclass(zone, rdclass);

	if (zonetype == dns_zone_slave) {
		dns_zone_addmaster(zone, &addr);
	}

	result = dns_zone_load(zone);
	ERRRET(result, "dns_zone_load");

	result = dns_zone_manage(zone, manager);
	ERRRET(result, "dns_zone_load");
}

static void
print_rdataset(dns_name_t *name, dns_rdataset_t *rdataset) {
        isc_buffer_t text;
        char t[1000];
        dns_result_t result;
        isc_region_t r;

        isc_buffer_init(&text, t, sizeof t, ISC_BUFFERTYPE_TEXT);
        result = dns_rdataset_totext(rdataset, name, ISC_FALSE, ISC_FALSE,
				     &text);
        isc_buffer_used(&text, &r);
        if (result == DNS_R_SUCCESS)
                printf("%.*s", (int)r.length, (char *)r.base);
        else
                printf("%s\n", dns_result_totext(result));
}

static void
query(void) {
	char buf[1024];
	dns_fixedname_t name;
	dns_fixedname_t found;
	dns_db_t *db;
	char *s;
	isc_buffer_t buffer;
	dns_result_t result;
	dns_rdataset_t rdataset;
	fd_set rfdset;

	db = dns_zone_getdb(zone);
	if (db == NULL) {
		fprintf(stderr, "db == NULL\n");
		return;
	}

	dns_fixedname_init(&found);
	dns_rdataset_init(&rdataset);

	do {
		
		fprintf(stdout, "zone_test ");
		fflush(stdout);
		FD_ZERO(&rfdset);
		FD_SET(0, &rfdset);
		select(1, &rfdset, NULL, NULL, NULL);
		if (fgets(buf, sizeof buf, stdin) == NULL) {
			fprintf(stdout, "\n");
			break;
		}
		buf[sizeof(buf) - 1] = '\0';
		
		s = strchr(buf, '\n');
		if (s != NULL)
			*s = '\0';
		s = strchr(buf, '\r');
		if (s != NULL)
			*s = '\0';
		if (strcmp(buf, "dump") == 0) {
			dns_zone_dump(zone, stdout);
			continue;
		}
		if (strlen(buf) == 0)
			continue;
		dns_fixedname_init(&name);
		isc_buffer_init(&buffer, buf, strlen(buf), ISC_BUFFERTYPE_TEXT);
		isc_buffer_add(&buffer, strlen(buf));
		result = dns_name_fromtext(dns_fixedname_name(&name),
				  &buffer, dns_rootname, ISC_FALSE, NULL);
		ERRCONT(result, "dns_name_fromtext");
		
		result = dns_db_find(db, dns_fixedname_name(&name),
				     NULL /*vesion*/,
				     dns_rdatatype_a,
				     0 /*options*/,
				     0 /*time*/,
				     NULL /*nodep*/,
				     dns_fixedname_name(&found),
				     &rdataset);
		fprintf(stderr, "%s() returned %s\n", "dns_db_find",
			dns_result_totext(result));
		switch (result) {
		case DNS_R_DELEGATION:
			print_rdataset(dns_fixedname_name(&found), &rdataset);
			break;
		case DNS_R_SUCCESS:
			print_rdataset(dns_fixedname_name(&name), &rdataset);
			break;
		default:
			continue;
		}

		dns_rdataset_disassociate(&rdataset);
	} while (1);
	dns_rdataset_invalidate(&rdataset);
}

static void
destroy(void) {
	if (zone == NULL)
		return;
	dns_zone_detach(&zone);
}

int
main(int argc, char **argv) {
	int c;
	char *filename = NULL;
	char *classname = "IN";

	while ((c = getopt(argc, argv, "cdf:m:qsMS")) != EOF) {
		switch (c) {
		case 'c':
			classname = optarg;
			break;
		case 'd':
			debug++;
			break;
		case 'f':
			if (filename != NULL)
				usage();
			filename = optarg;
			break;
		case 'm':
			memset(&addr, 0, sizeof addr);
			addr.type.sin.sin_family = AF_INET;
			inet_pton(AF_INET, optarg, &addr.type.sin.sin_addr);
			addr.type.sin.sin_port = htons(53);
			break;
		case 'q':
			quiet++;
			break;
		case 's':
			stats++;
			break;
		case 'S':
			zonetype = dns_zone_slave;
			break;
		case 'M':
			zonetype = dns_zone_master;
			break;
		default:
			usage();
		}
	}

	if (argv[optind] == NULL)
		usage();

	RUNTIME_CHECK(isc_app_start() == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_taskmgr_create(mctx, 2, 0, &manager) ==
		      ISC_R_SUCCESS);

	if (filename == NULL)
		filename = argv[optind];
	setup(argv[optind], filename, classname);
	query();
	destroy();
	isc_taskmgr_destroy(&manager);
	if (!quiet && stats)
		isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	exit(0);
}
