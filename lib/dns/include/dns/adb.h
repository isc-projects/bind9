
/***** 
 ***** Module Info 
 *****/ 


/*
 * DNS Address Database
 *
 * This module implements an address database (ADB) for mapping an
 * NS rdata record to an isc_sockaddr_t. It also provides statistical
 * information on how good that address might be.
 *
 * A client will pass in an rdataset (of NS records) requesting all the
 * addresses (isc_sockaddr_t) for the NS records inside. The ADB will walk
 * through the rdataset looking up addresses associated with each name.
 * If it is found on the internal lists, a structure is filled in with
 * the address information and stats for that address.
 *
 * If the address cannot be found on the internal lists, a new entry will
 * be created for an address if all the information needed can be found
 * in the zone table or cache.  This new address will then be returned.
 *
 * If a request must be made to remote servers to satisfy an address lookup,
 * this module will start fetches to try to complete these addresses.  When
 * at least one more completes, an event is sent to the caller.  If none of
 * them resolve before the fetch times out, an event indicating this is
 * sent instead.
 *
 * Records are stored internally until a timer expires. The timer is the
 * smaller of the TTL or signature validity period. For A6 records, the timer
 * is the smallest of all the TTL or signature validity periods in the A6
 * chain.
 *
 * Lameness is stored per-zone, and this data hangs off each address field.
 * When an address is marked lame for a given zone the address will not
 * be returned to a caller.
 *
 *
 * MP:
 *
 *     The ADB takes care of all necessary locking. 
 *
 *
 * Reliability:
 *
 *     XXX Dunno yet. Need something here.
 *
 * Security:
 *
 *	None, since all data stored is required to be pre-filtered.
 *	(Cache needs to be sane, fetches return bounds-checked and sanity-
 *	checked data, caller passes a good dns_name_t for the zone, etc)
 */

/* 
 * TODO:
 *
 *   - Should the public type be a handle to a reference counted type?
 *
 */


/***
 *** TYPES
 ***/

/* _The_ ADB */
typedef struct dns_adb dns_adb_t;

/*
 * The handle into our internal state of what is going on, where, when...
 * This is returned to the user as a handle, so requests can be canceled,
 * etc.
 */
typedef struct dns_adbhandle dns_adbhandle_t;

/*
 * Purely internal type.
 */
typedef struct dns_adbentry dns_adbentry_t;

/* The answers to queries come back as a list of these. */
typedef struct dns_adbaddr dns_adbaddr_t;
typedef ISC_LIST(dns_adbaddr_t) dns_adbaddrlist_t;
struct dns_adbaddr {
	ISC_LINK(dns_adbaddr_t)		link;
	isc_sockaddr_t		       *sockaddr;
	int				goodness;
	unsigned int			srtt; /* microseconds */
	unsigned int			flags;
	unsigned int			hostid;
	dns_adbentry_t		       *entry;
};

/*
 * The event sent to the caller task is just a plain old isc_event_t.  It
 * contains no data other than a simple status, passed in the "type" field
 * to indicate that another address resolved, or all partially resolved
 * addresses have failed to resolve.
 *
 * "sender" is the dns_adbhandle_t used to issue this query.
 *
 * This is simply a standard event, with the "type" set to:
 *
 *	DNS_EVENT_MOREADDRESSES   -- another address resolved.
 *	DNS_EVENT_NOMOREADDRESSES -- all pending addresses failed,
 *		       		     were canceled, or otherwise will
 *				     not be usable.
 */

/****
 **** FUNCTIONS
 ****/

/*
 * Create a new ADB.
 *
 * Requires:
 *
 *	'mem' must be a pointer to a valid memory manager that all internal
 *	allocations will happen through (and so must remain valid at least
 *	until the new isc_addrtable_t is deleted)
 *
 * Returns:
 *
 *	ISC_R_SUCCESS	after happiness
 *	ISC_R_NOMEMORY	after resource allocation failure.
 *
 */
isc_result_t
dns_adb_create(isc_mem_t *mem, dns_adb_t **newadb);


/*
 * Delete the ADB. Sets *ADB to NULL. Cancels any outstanding requests.
 *
 * Requires:
 *
 *	'adb' be non-NULL and '*adb' be a valid dns_adb_t, created via
 *	dns_adb_create().
 *
 */
void
dns_adb_destroy(isc_adb_t **adb);


/*
 * Main interface for clients. The adb will iterate over the rdata items in
 * NSDATASET and will build up a list of found addresses, and perhaps start
 * internal fetches to resolve names that are unknown currently.
 *
 * If other addresses resolve after this call completes, an event will
 * be sent to the <task, taskaction, arg> with the sender of that event
 * set to a pointer to the dns_adbhandle_t returned by this function.
 *
 * The events must be canceled using either dns_adb_cancel() or
 * dns_adb_done().  dns_adb_cancel() will cancel internal fetches as well
 * as stop events from being delivered.  dns_adb_done() may leave them
 * running (with the task passed here) after returning.  Calling either will
 * ensure that no more events are delivered, and pending events will be
 * removed from the task's queue.
 *
 * The list of addresses returned is unordered.  The caller must impose
 * any ordering required.  The list will not contain "known bad" addresses,
 * however.  For instance, it will not return hosts that are known to be
 * lame for the zone in question.
 *
 * The caller cannot (directly) modify the contents of the address list's
 * fields other than the "link" field.  All values can be read at any
 * time, however.
 *
 * Requires:
 *
 *	*adb be a valid isc_adb_t object.
 *
 *	*task be a valid task, and isc_taskaction_t != NULL.
 *
 *	*nsdataset be a valid dns_rdataset_t with a non-zero number of NS
 *	 records in it.
 *
 *	addrlist != NULL && *addrlist == NULL.
 *
 *	handle != NULL && *handle == NULL.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS	Addresses might have been returned, and events will be
 *			delivered for unresolved addresses.
 *	ISC_R_NOMORE	Addresses might have been returned, but no events
 *			will ever be posted for this context.
 *	ISC_R_NOMEMORY	insufficient resources
 *	ISC_R_FAILURE	there weren't any NS records found in the nsdataset.
 *
 * Ensures:
 *
 *	No internal reference to "nsrdataset" exists after this function
 *	returns.
 */
isc_result_t
dns_adb_lookup(isc_adb_t *adb, isc_task_t *task, isc_taskaction_t *action,
	       void *arg, dns_rdataset_t *nsdataset, dns_name_t *zone,
	       dns_adbhandle_t **handle);

/*
 * Cancels any outstanding lookups for this handle.
 *
 * Requires:
 *
 *	'adb' be a valid dns_adb_t pointer.
 *
 *	'adbhandle' be valid dns_adbhandle_t pointer.
 *
 * Ensures:
 *
 *	No "address found" events will be posted to the originating task
 *	after this function returns, and all internal uses of that task
 *	will be quickly shut down.
 */
void
dns_adb_cancel(dns_adb_t *adb, dns_adbhandle_t *adbhandle);

/*
 * Stops any internal lookups for this handle.
 *
 * Requires:
 *
 *	'adb' be a valid dns_adb_t pointer.
 *
 *	'adbhandle' be valid dns_adbhandle_t pointer.
 *
 * Ensures:
 *
 *	No "address found" events will be posted to the originating task
 *	after this function returns.
 *
 * Note:
 *
 *	The task used to launch this handle can be used internally for
 *	a short time after this function returns.
 */
void
dns_adb_done(dns_adb_t *adb, dns_adbhandle_t *adbhandle);


/*
 * Need functions/macros to:
 *
 *	Remove an address from a handle's linked list.  This is needed
 *	because the data pointed to by a dns_adbaddr_t is reference counted.
 *
 *	Adjust the goodness, both local and globally.
 *
 *	Mark an entry as lame.
 *
 *	set/clear various flags.  (Which flags?)
 *
 *	Mix in measured RTT values.
 */
