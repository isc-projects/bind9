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

#ifndef DNS_JOURNAL_H
#define DNS_JOURNAL_H 1

/*****
 ***** Module Info
 *****/

/*
 * Database journalling.
 */

/***
 *** Imports
 ***/

#include <isc/types.h>

#include <dns/result.h>
#include <dns/types.h>
#include <dns/name.h>
#include <dns/rdata.h>

/***
 *** Types
 ***/

ISC_LANG_BEGINDECLS

/*
 * A dns_difftuple_t represents a single RR being added or deleted.
 * The RR type and class are in the 'rdata' member; the class is always
 * the real one, not a DynDNS meta-class, so that the rdatas can be
 * compared using dns_rdata_compare().  The TTL is significant 
 * even for deletions, because a deletion/addition pair cannot
 * be canceled out if the TTL differs (it might be an explicit
 * TTL update).
 *
 * Tuples are also used to represent complete RRs with owner
 * names for a couple of other purposes, such as the 
 * individual RRs of a "RRset exists (value dependent)"
 * prerequisite set.  In this case, op==DNS_DIFFOP_EXISTS,
 * and the TTL is ignored.
 */

typedef enum {
	DNS_DIFFOP_ADD,	        /* Add an RR. */
	DNS_DIFFOP_DEL,		/* Delete an RR. */
	DNS_DIFFOP_EXISTS	/* Assert RR existence. */
} dns_diffop_t;

typedef struct dns_difftuple dns_difftuple_t;

#define DNS_DIFFTUPLE_MAGIC	0x44494654U	/* DIFT. */
#define DNS_DIFFTUPLE_VALID(t)	((t) != NULL && \
				 (t)->magic == DNS_DIFFTUPLE_MAGIC)

struct dns_difftuple {
        unsigned int			magic;
	isc_mem_t			*mctx;
	dns_diffop_t			op;        
	dns_name_t			name;
	dns_ttl_t			ttl;
	dns_rdata_t			rdata;
	ISC_LINK(dns_difftuple_t)	link;
	/* Variable-size name data and rdata follows. */
};

/*
 * A dns_diff_t represents a set of changes being applied to
 * a zone.  Diffs are also used to represent "RRset exists 
 * (value dependent)" prerequisites.
 */
typedef struct dns_diff dns_diff_t;

#define DNS_DIFF_MAGIC		0x44494646U	/* DIFF. */
#define DNS_DIFF_VALID(t)	((t) != NULL && \
					 (t)->magic == DNS_DIFF_MAGIC)

struct dns_diff {
	unsigned int			magic;
	isc_mem_t *			mctx;
	ISC_LIST(dns_difftuple_t)	tuples;
};

/* Type of comparision function for sorting diffs. */
typedef int dns_diff_compare_func(const void *, const void *);

/*
 * A dns_journal_t represents an open journal file.  This is an opaque type.
 *
 * A particular dns_journal_t object may be opened for writing, in which case
 * it can be used for writing transactions to a journal file, or it can be
 * opened for reading, in which case it can be used for reading transactions
 * from (iterating over) a journal file.  A single dns_journal_t object may
 * not be used for both purposes.
 */
typedef struct dns_journal dns_journal_t;


/***
 *** Functions
 ***/

/**************************************************************************/
/*
 * Maniuplation of diffs and tuples.
 */

isc_result_t
dns_difftuple_create(isc_mem_t *mctx,
		     dns_diffop_t op, dns_name_t *name, dns_ttl_t ttl,
		     dns_rdata_t *rdata, dns_difftuple_t **tp);
/*
 * Create a tuple.  Deep copies are made of the name and rdata, so
 * they need not remain valid after the call.
 *
 * Requires:
 *	*tp != NULL && *tp == NULL.
 *
 * Returns:
 *	ISC_R_SUCCESS
 *      ISC_R_NOMEMORY
 */

void
dns_difftuple_free(dns_difftuple_t **tp);
/*
 * Free a tuple.
 *
 * Requires:
 *       **tp is a valid tuple.
 *
 * Ensures:
 *       *tp == NULL
 *       All memory used by the tuple is freed.
 */

isc_result_t
dns_difftuple_copy(dns_difftuple_t *orig, dns_difftuple_t **copyp);
/*
 * Copy a tuple.
 *
 * Requires:
 * 	'orig' points to a valid tuple 
 *	copyp != NULL && *copyp == NULL
 */

void dns_diff_init(isc_mem_t *mctx, dns_diff_t *diff);
/*
 * Initialize a diff.
 *
 * Requires:
 *    'diff' points to an uninitialized dns_diff_t
 *    allocated by the caller.
 *
 * Ensures:
 *    '*diff' is a valid, empty diff.
 */ 

void dns_diff_clear(dns_diff_t *diff);
/*
 * Clear a diff, destroying all its tuples.
 *
 * Requires:
 *    'diff' points to a valid dns_diff_t.
 *
 * Ensures:
 *     Any tuples in the diff are destroyed.
 *     The diff now empty, but it is still valid
 *     and may be reused without calling dns_diff_init
 *     again.  The only memory used is that of the
 *     dns_diff_t structure itself.
 *
 * Notes:
 *     Managing the memory of the dns_diff_t structure itself
 *     is the caller's responsibility.
 */

void
dns_diff_append(dns_diff_t *diff, dns_difftuple_t **tuple);
/*
 * Append a single tuple to a diff.
 *
 *	'diff' is a valid diff.
 * 	'*tuple' is a valid tuple.
 *
 * Ensures:
 *	*tuple is NULL.
 *	The tuple has been freed, or will be freed when the diff is cleared.
 */

void
dns_diff_appendminimal(dns_diff_t *diff, dns_difftuple_t **tuple);
/*
 * Append 'tuple' to 'diff', removing any duplicate
 * or conflicting updates as needed to create a minimal diff.
 *
 * Requires:
 *	'diff' is a minimal diff.
 *
 * Ensures:
 *	'diff' is still a minimal diff.
 *   	*tuple is NULL.
 *   	The tuple has been freed, or will be freed when the diff is cleared.
 *
 */

isc_result_t
dns_diff_sort(dns_diff_t *diff, dns_diff_compare_func *compare);
/*
 * Sort 'diff' in-place according to the comparison function 'compare'.
 */

isc_result_t 
dns_diff_apply(dns_diff_t *diff, dns_db_t *db, dns_dbversion_t *ver);
/*
 * Apply 'diff' to the database 'db'.
 *
 * For efficiency, the diff should be sorted by owner name.
 * If it is not sorted, operation will still be correct,
 * but less efficient.
 *
 * Requires:
 *	*diff is a valid diff (possibly empty), containing
 *   	tuples of type DNS_DIFFOP_ADD and/or 
 *   	For DNS_DIFFOP_DEL tuples, the TTL is ignored.
 *
 */

isc_result_t 
dns_diff_load(dns_diff_t *diff, dns_addrdatasetfunc_t addfunc,
	      void *add_private);
/*
 * Like dns_diff_apply, but for use when loading a new database
 * instead of modifying an existing one.  This bypasses the
 * database transaction mechanisms.
 *
 * Requires:
 * 	'addfunc' is a valid dns_addradatasetfunc_t obtained from
 * 	dns_db_beginload()
 * 
 *	'add_private' points to a corresponding dns_dbload_t *
 *      (XXX why is it a void pointer, then?)
 */

isc_result_t
dns_diff_print(dns_diff_t *diff, FILE *file);

/* 
 * Print the differences to 'file' or if 'file' is NULL via the
 * logging system.
 *
 * Require:
 *	'diff' to be valid.
 *	'file' to refer to a open file or NULL.
 *
 * Returns:
 *	DNS_R_SUCCESS
 *	DNS_R_NOMEMORY
 *	DNS_R_UNEXPECTED
 *	any error from dns_rdataset_totext()
 */
	
/**************************************************************************/
/* 
 * Misc. utilities
 * XXX these belong in a general-purpose DNS library
 */

isc_uint32_t dns_soa_getserial(dns_rdata_t *rdata);
/*
 * Extract the serial number from the rdata of a SOA record.
 *  
 * Requires:
 *	rdata refers to the rdata of a well-formed SOA record.
 */

void dns_soa_setserial(isc_uint32_t val, dns_rdata_t *rdata);
/*
 * Change the serial number of a SOA record by modifying the
 * rdata in-place.
 *
 * Requires:
 *	rdata refers to the rdata of a well-formed SOA record.
 */

isc_result_t
dns_db_getsoaserial(dns_db_t *db, dns_dbversion_t *ver, isc_uint32_t *serialp);
/*
 * Get the current SOA serial number from a zone database.
 *
 * Requires:
 *      'db' is a valid database with zone semantics.
 *      'ver' is a valid version.
 */

isc_result_t
dns_db_createsoatuple(dns_db_t *db, dns_dbversion_t *ver, isc_mem_t *mctx,
		   dns_diffop_t op, dns_difftuple_t **tp);
/*
 * Create a diff tuple for the current database SOA.
 */


#define DNS_SERIAL_GT(a, b) ((int)(((a) - (b)) & 0xFFFFFFFF) > 0)
#define DNS_SERIAL_GE(a, b) ((int)(((a) - (b)) & 0xFFFFFFFF) >= 0)
/*
 * Compare SOA serial numbers.  DNS_SERIAL_GT(a, b) returns true iff 
 * a is "greater than" b where "greater than" is as defined in RFC1982.
 * DNS_SERIAL_GE(a, b) returns true iff a is "greater than or equal to" b.
 */

/**************************************************************************/
/*
 * Journal object creation and destruction.
 */

isc_result_t
dns_journal_open(isc_mem_t *mctx, const char *filename, isc_boolean_t write,
		 dns_journal_t **journalp);
/*
 * Open the journal file 'filename' and create a dns_journal_t object for it.
 *
 * If 'write' is ISC_TRUE, the journal is open for writing.  If it does 
 * not exist, it is created.
 *
 * If 'write' is ISC_FALSE, the journal is open for reading.  If it does 
 * not exist, ISC_R_NOTFOUND is returned.
 */

void
dns_journal_destroy(dns_journal_t **journalp);
/*
 * Destroy a dns_journal_t, closing any open files and freeing its memory.
 */

/**************************************************************************/
/*
 * Writing transactions to journals.
 */

isc_result_t
dns_journal_begin_transaction(dns_journal_t *j);
/*
 * Prepare to write a new transaction to the open journal file 'j'.
 *
 * Requires:
 *      'j' is open for writing.
 */

isc_result_t
dns_journal_writediff(dns_journal_t *j, dns_diff_t *diff);
/*
 * Write 'diff' to the current transaction of journal file 'j'.
 *
 * Requires:
 *      'j' is open for writing and dns_journal_begin_transaction()
 * 	has been called.
 * 
 * 	'diff' is a full or partial, correctly ordered IXFR
 *      difference sequence.
 */

isc_result_t
dns_journal_commit(dns_journal_t *j);
/*
 * Commit the current transaction of journal file 'j'.
 *
 * Requires:
 *      'j' is open for writing and dns_journal_begin_transaction()
 * 	has been called.
 *
 *      dns_journal_writediff() has been called one or more times
 * 	to form a complete, correctly ordered IXFR difference
 *      sequence.
 */

isc_result_t
dns_journal_write_transaction(dns_journal_t *j, dns_diff_t *diff);
/*
 * Write a complete transaction at once to a journal file,
 * sorting it if necessary, and commit it.  Equivalent to calling
 * dns_diff_sort(), dns_journal_begin_transaction(),
 * dns_journal_writediff(), and dns_journal_commit().
 *
 * Requires:
 *      'j' is open for writing.
 *
 * 	'diff' contains exactly one SOA deletion, one SOA addition
 *       with a greater serial number, and possibly other changes,
 *       in arbitrary order.
 */

/**************************************************************************/
/*
 * Reading transactions from journals.
 */

isc_uint32_t dns_journal_first_serial(dns_journal_t *j);
isc_uint32_t dns_journal_last_serial(dns_journal_t *j);
/*
 * Get the first and last addressable serial number in the journal.
 */

isc_result_t
dns_journal_iter_init(dns_journal_t *j,
		      isc_uint32_t begin_serial, isc_uint32_t end_serial);
/*
 * Prepare to iterate over the transactions that will bring the database
 * from SOA serial number 'begin_serial' to 'end_serial'.
 *
 * Returns:
 *	DNS_R_SUCCESS	
 *	DNS_R_NOTFOUND	begin_serial is within the range of adressable
 *			serial numbers covered by the journal, but
 *			this particular serial number does not exist.
 *	DNS_R_RANGE	begin_serial is outside the addressable range.
 */

isc_result_t dns_journal_first_rr(dns_journal_t *j);
isc_result_t dns_journal_next_rr(dns_journal_t *j);
/*
 * Position the iterator at the first/next RR in a journal
 * transaction sequence established using dns_journal_iter_init().
 *
 * Requires:
 *      dns_journal_iter_init() has been called.
 *
 */

void dns_journal_current_rr(dns_journal_t *j, dns_name_t **name, 
			    isc_uint32_t *ttl, dns_rdata_t **rdata);
/*
 * Get the name, ttl, and rdata of the current journal RR.
 *
 * Requires:
 *      The last call to dns_journal_first_rr() or dns_journal_next_rr()
 *      returned DNS_R_SUCCESS.
 */

/**************************************************************************/
/*
 * Database roll-forward.
 */

isc_result_t
dns_journal_rollforward(isc_mem_t *mctx, dns_db_t *db, const char *filename);
/*
 * Roll forward (play back) the journal file "filename" into the
 * database "db".  This should be called when the server starts
 * after a shutdown or crash.
 *
 * Requires:
 *      'mctx' is a valid memory context.
 *	'db' is a valid database which does not have a version
 *           open for writing.
 *      'filename' is the name of the journal file belonging to 'db'.
 *
 * Returns:
 *	DNS_R_NOJOURNAL when journal does not exist.
 *	DNS_R_NOTFOUND when current serial in not in journal.
 *	DNS_R_SUCCESS journal has been applied successfully to database.
 *	others
 */

isc_result_t dns_journal_print(isc_mem_t *mctx, const char *filename, FILE *file);
/* For debugging not general use */

isc_result_t
dns_db_diff(isc_mem_t *mctx,
	    dns_db_t *dba, dns_dbversion_t *dbvera,
	    dns_db_t *dbb, dns_dbversion_t *dbverb,
	    const char *journal_filename);
/*
 * Compare the databases 'dba' and 'dbb' and generate a journal
 * entry containing the changes to make 'dba' from 'dbb' (note
 * the order).  This journal entry will consist of a single,
 * possibly very large transaction.  Append the journal
 * entry to the journal file specified by 'journal_filename'.
 */ 


ISC_LANG_ENDDECLS

#endif /* DNS_JOURNAL_H */
