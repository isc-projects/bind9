/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef NS_HOOKS_H
#define NS_HOOKS_H 1

/*! \file */

#include <stdbool.h>

#include <isc/list.h>
#include <isc/magic.h>
#include <isc/result.h>

#include <dns/rdatatype.h>

#include <ns/client.h>
#include <ns/query.h>
/*
 * Hooks provide a way of running a callback function once a certain place in
 * code is reached.  Current use is limited to libns unit tests and thus:
 *
 *   - hook-related types and macros are not placed in libns header files,
 *   - hook-related code is compiled away unless --with-atf is used,
 *   - hook-related macro names are prefixed with "NS_".
 *
 * However, the implementation is pretty generic and could be repurposed for
 * general use, e.g. as part of libisc, after some further customization.
 *
 * Hooks are created by inserting a macro into any function returning
 * isc_result_t (NS_PROCESS_HOOK()) or void (NS_PROCESS_HOOK_VOID()).  As both
 * of these macros contain a return statement which is inlined into the
 * function into which the hook is inserted, a hook callback is able to cause
 * that function to return at hook insertion point.  For functions returning
 * isc_result_t, if a hook callback intends to cause a return at hook insertion
 * point, it also has to set the value to be returned by the function.
 *
 * Hook callbacks are functions which:
 *
 *   - return a boolean value; if true is returned by the callback, the
 *     function into which the hook is inserted will return at hook insertion
 *     point; if false is returned by the callback, execution of the
 *     function into which the hook is inserted continues normally,
 *
 *   - accept three pointers as arguments:
 *
 *       - a pointer specified by the hook itself,
 *       - a pointer specified upon inserting the callback into the hook table,
 *       - a pointer to isc_result_t which will be returned by the function
 *         into which the hook is inserted if the callback returns true.
 *
 * Hook tables are arrays which consist of a number of tuples (one tuple per
 * hook identifier), each of which determines the callback to be invoked when a
 * given hook is processed and the data to be passed to that callback.  In an
 * attempt to keep things as simple as possible, current implementation uses
 * hook tables which are statically-sized arrays only allowing a single
 * callback to be invoked for each hook identifier.
 *
 * In order for a hook callback to be called for a given hook, a pointer to
 * that callback (along with an optional pointer to callback-specific data) has
 * to be inserted into the relevant hook table entry for that hook.  Replacing
 * whole hook tables is also possible.
 *
 * Consider the following sample code:
 *
 * ----------------------------------------------------------------------------
 * ns_hook_t *foo_hook_table = NULL;
 *
 * isc_result_t
 * foo_bar(void) {
 *     int val = 42;
 *
 *     ...
 *
 *     NS_PROCESS_HOOK(foo_hook_table, FOO_EXTRACT_VAL, &val);
 *
 *     ...
 *
 *     printf("This message may not be printed due to use of hooks.");
 *
 *     return (ISC_R_SUCCESS);
 * }
 *
 * bool
 * cause_failure(void *hook_data, void *callback_data, isc_result_t *resultp) {
 *     int *valp = (int *)hook_data;
 *     bool *calledp = (bool *)callback_data;
 *
 *     ...
 *
 *     *resultp = ISC_R_FAILURE;
 *
 *     return (true);
 * }
 *
 * bool
 * examine_val(void *hook_data, void *callback_data, isc_result_t *resultp) {
 *     int *valp = (int *)hook_data;
 *     int *valcopyp = (int *)callback_data;
 *
 *     UNUSED(resultp);
 *
 *     ...
 *
 *     return (false);
 * }
 *
 * void
 * test_foo_bar(void) {
 *     bool called = false;
 *     int valcopy;
 *
 *     ns_hook_t my_hooks[FOO_HOOKS_COUNT] = {
 *         [FOO_EXTRACT_VAL] = {
 *             .callback = cause_failure,
 *             .callback_data = &called,
 *         },
 *     };
 *
 *     foo_hook_table = my_hooks;
 *     foo_bar();
 *
 *     {
 *         const ns_hook_t examine_hook = {
 *             .callback = examine_val,
 *             .callback_data = &valcopy,
 *         };
 *
 *         my_hooks[FOO_EXTRACT_VAL] = examine_hook;
 *     }
 *     foo_bar();
 *
 * }
 * ----------------------------------------------------------------------------
 *
 * When test_foo_bar() is called, "foo_hook_table" is set to "my_hooks".  Then
 * foo_bar() gets invoked.  Once execution reaches the insertion point for hook
 * FOO_EXTRACT_VAL, cause_failure() will be called with &val as "hook_data" and
 * &called as "callback_data".  It can do whatever it pleases with these two
 * values.  Eventually, cause_failure() sets *resultp to ISC_R_FAILURE and
 * returns true, which causes foo_bar() to return ISC_R_FAILURE and never
 * execute the printf() call below hook insertion point.
 *
 * Execution then returns to test_foo_bar().  Unlike before the first call to
 * foo_bar(), this time only a single hook ("examine_hook") is defined instead
 * of a complete hook table.  This hook is then subsequently inserted at index
 * FOO_EXTRACT_VAL into the "my_hook" hook table.  This causes the hook
 * previously set at that index (the one calling cause_failure()) to be
 * replaced with "examine_hook".  Thus, when the second call to foo_bar() is
 * subsequently made, examine_val() will be called with &val as "hook_data" and
 * &valcopy as "callback_data".  Contrary to cause_failure(), extract_val()
 * returns false, which means it does not access "resultp" and does not
 * cause foo_bar() to return at hook insertion point.  Thus, printf() will be
 * called this time and foo_bar() will return ISC_R_SUCCESS.
 */

/*!
 * Currently-defined hook points. So long as these are unique,
 * the order in which they are declared is unimportant, but
 * currently matches the order in which they are referenced in
 * query.c.
 */
typedef enum {
	/* hookpoints from query.c */
	NS_QUERY_QCTX_INITIALIZED,
	NS_QUERY_QCTX_DESTROYED,
	NS_QUERY_SETUP,
	NS_QUERY_START_BEGIN,
	NS_QUERY_LOOKUP_BEGIN,
	NS_QUERY_RESUME_BEGIN,
	NS_QUERY_GOT_ANSWER_BEGIN,
	NS_QUERY_RESPOND_ANY_BEGIN,
	NS_QUERY_RESPOND_ANY_FOUND,
	NS_QUERY_RESPOND_BEGIN,
	NS_QUERY_NOTFOUND_BEGIN,
	NS_QUERY_PREP_DELEGATION_BEGIN,
	NS_QUERY_ZONE_DELEGATION_BEGIN,
	NS_QUERY_DELEGATION_BEGIN,
	NS_QUERY_NODATA_BEGIN,
	NS_QUERY_NXDOMAIN_BEGIN,
	NS_QUERY_CNAME_BEGIN,
	NS_QUERY_DNAME_BEGIN,
	NS_QUERY_PREP_RESPONSE_BEGIN,
	NS_QUERY_DONE_BEGIN,
	NS_QUERY_DONE_SEND,

	/* XXX other files could be added later */

	NS_HOOKPOINTS_COUNT	/* MUST BE LAST */
} ns_hookpoint_t;

typedef bool
(*ns_hook_action_t)(void *arg, void *data, isc_result_t *resultp);

typedef struct ns_hook {
	isc_mem_t *mctx;
	ns_hook_action_t action;
	void *action_data;
	ISC_LINK(struct ns_hook) link;
} ns_hook_t;

typedef ISC_LIST(ns_hook_t) ns_hooklist_t;
typedef ns_hooklist_t ns_hooktable_t[NS_HOOKPOINTS_COUNT];

/*%
 * ns__hook_table is a global hook table, which is used if view->hooktable
 * is NULL.  It's intended only for use by unit tests.
 */
LIBNS_EXTERNAL_DATA extern ns_hooktable_t *ns__hook_table;

/*!
 * Context for initializing a hook module.
 *
 * This structure passes data to which a hook module will need
 * access -- server memory context, hash initializer, log context, etc.
 * The structure doesn't persist beyond configuring the hook module.
 * The module's register function should attach to all reference-counted
 * variables and its destroy function should detach from them.
 */
typedef struct ns_hookctx {
	unsigned int		magic;
	isc_mem_t		*mctx;
	isc_log_t		*lctx;
} ns_hookctx_t;

#define NS_HOOKCTX_MAGIC	ISC_MAGIC('H', 'k', 'c', 'x')
#define NS_HOOKCTX_VALID(h)	ISC_MAGIC_VALID(h, NS_HOOKCTX_MAGIC)

/*
 * API version
 *
 * When the API changes, increment NS_HOOK_VERSION. If the
 * change is backward-compatible (e.g., adding a new function call
 * but not changing or removing an old one), increment NS_HOOK_AGE
 * as well; if not, set NS_HOOK_AGE to 0.
 */
#ifndef NS_HOOK_VERSION
#define NS_HOOK_VERSION 1
#define NS_HOOK_AGE 0
#endif

typedef isc_result_t ns_hook_register_t(const char *parameters,
					const char *file,
					unsigned long line,
					const void *cfg,
					void *actx,
					ns_hookctx_t *hctx,
					ns_hooktable_t *hooktable,
					void **instp);
/*%<
 * Called when registering a new module.
 *
 * 'parameters' contains the module configuration text.
 *
 * '*instp' will be set to the module instance handle if the function
 * is successful.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *\li	Other errors are possible
 */

typedef void ns_hook_destroy_t(void **instp);
/*%<
 * Destroy a module instance.
 *
 * '*instp' must be set to NULL by the function before it returns.
 */

typedef int ns_hook_version_t(void);
/*%<
 * Return the API version number a hook module was compiled with.
 *
 * If the returned version number is no greater than
 * NS_HOOK_VERSION, and no less than NS_HOOK_VERSION - NS_HOOK_AGE,
 * then the module is API-compatible with named.
 */

/*%
 * Prototypes for API functions to be defined in each module.
 */
ns_hook_destroy_t hook_destroy;
ns_hook_register_t hook_register;
ns_hook_version_t hook_version;

isc_result_t
ns_hook_createctx(isc_mem_t *mctx, ns_hookctx_t **hctxp);

void
ns_hook_destroyctx(ns_hookctx_t **hctxp);
/*%<
 * Create/destroy a hook module context.
 */

isc_result_t
ns_hookmodule_load(const char *modpath, const char *parameters,
		   const char *cfg_file, unsigned long cfg_line,
		   const void *cfg, void *actx,
		   ns_hookctx_t *hctx, ns_hooktable_t *hooktable);
/*%<
 * Load the hook module specified from the file 'modpath', using
 * parameters 'parameters'.
 *
 * 'cfg_file' and 'cfg_line' specify the location of the hook module
 * declaration in the configuration file.
 *
 * 'cfg' and 'actx' are the configuration context and ACL configuration
 * context, respectively; they are passed as void * here in order to
 * prevent this library from having a dependency on libisccfg).
 *
 * 'hctx' is the hook context and 'hooktable' is the hook table
 * into which hook points should be registered.
 */

void
ns_hookmodule_unload_all(void);
/*%<
 * Unload all currently loaded hook modules.
 */

void
ns_hook_add(ns_hooktable_t *hooktable, isc_mem_t *mctx,
	    ns_hookpoint_t hookpoint, const ns_hook_t *hook);
/*%<
 * Allocate (using memory context 'mctx') a copy of the 'hook' structure
 * describing a hook callback and append it to the list of hooks at 'hookpoint'
 * in 'hooktable'.
 *
 * Requires:
 *\li 'hooktable' is not NULL
 *
 *\li 'mctx' is not NULL
 *
 *\li 'hookpoint' is less than NS_QUERY_HOOKS_COUNT
 *
 *\li 'hook' is not NULL
 */

void
ns_hooktable_init(ns_hooktable_t *hooktable);
/*%<
 * Initialize a hook table.
 */

isc_result_t
ns_hooktable_create(isc_mem_t *mctx, ns_hooktable_t **tablep);
/*%<
 * Allocate and initialize a hook table.
 */

void
ns_hooktable_free(isc_mem_t *mctx, void **tablep);
/*%<
 * Free a hook table.
 */

#endif /* NS_HOOKS_H */
