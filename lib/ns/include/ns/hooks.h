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
#include <isc/result.h>

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

typedef enum {
	NS_QUERY_SETUP_QCTX_INITIALIZED,
	NS_QUERY_START_BEGIN,
	NS_QUERY_LOOKUP_BEGIN,
	NS_QUERY_RESUME_BEGIN,
	NS_QUERY_PREP_RESPONSE_BEGIN,
	NS_QUERY_RESPOND_ANY_BEGIN,
	NS_QUERY_RESPOND_ANY_FOUND,
	NS_QUERY_RESPOND_ANY_NOT_FOUND,
	NS_QUERY_RESPOND_BEGIN,
	NS_QUERY_GOT_ANSWER_BEGIN,
	NS_QUERY_NOTFOUND_BEGIN,
	NS_QUERY_PREP_DELEGATION_BEGIN,
	NS_QUERY_ZONE_DELEGATION_BEGIN,
	NS_QUERY_DELEGATION_BEGIN,
	NS_QUERY_NODATA_BEGIN,
	NS_QUERY_NXDOMAIN_BEGIN,
	NS_QUERY_CNAME_BEGIN,
	NS_QUERY_DNAME_BEGIN,
	NS_QUERY_ADDITIONAL_BEGIN,
	NS_QUERY_DONE_BEGIN,
	NS_QUERY_DONE_SEND,
	NS_QUERY_HOOKS_COUNT	/* MUST BE LAST */
} ns_hookpoint_t;

typedef bool
(*ns_hook_cb_t)(void *hook_data, void *callback_data, isc_result_t *resultp);

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

typedef isc_result_t ns_hook_register_t(isc_mem_t *mctx,
					const char *parameters,
					const char *file,
					unsigned long line,
					void **instp);
/*%
 * Called when registering a new module.
 *
 * 'parameters' contains the driver configuration text.
 *
 * '*instp' will be set to the driver instance handle if the function
 * is successful.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *\li	Other errors are possible
 */

typedef void ns_hook_destroy_t(void **instp);
/*%
 * Destroy a module instance.
 *
 * \c *instp must be set to \c NULL by the function before it returns.
 */

typedef int ns_hook_version_t(unsigned int *flags);
/*%
 * Return the API version number a hook module was compiled with.
 *
 * If the returned version number is no greater than than
 * NS_HOOK_VERSION, and no less than NS_HOOK_VERSION - NS_HOOK_AGE,
 * then the module is API-compatible with named.
 *
 * 'flags' is currently unused and may be NULL, but could be used in
 * the future to pass back driver capabilities or other information.
 */

typedef struct ns_hook {
	ns_hook_cb_t callback;
	void *callback_data;
	ISC_LINK(struct ns_hook) link;
} ns_hook_t;

/*
 * ns__hook_table is a globally visible pointer to the active hook
 * table. It's initialized to point to 'hooktab', which is the default
 * global hook table.
 */
typedef ISC_LIST(ns_hook_t) ns_hooklist_t;
typedef ns_hooklist_t ns_hooktable_t[NS_QUERY_HOOKS_COUNT];
LIBNS_EXTERNAL_DATA extern ns_hooktable_t *ns__hook_table;

/*
 * Run a hook. Calls the function or functions registered at hookpoint 'id'.
 * If one of them returns true, we interrupt processing and return the
 * result that was returned by the hook function. If none of them return
 * true, we continue processing.
 */
#define _NS_PROCESS_HOOK(table, id, data, ...)				\
	if (table != NULL) {			\
		ns_hook_t *_hook = ISC_LIST_HEAD((*table)[id]);		\
		isc_result_t _result;					\
									\
		while (_hook != NULL) {					\
			ns_hook_cb_t _callback = _hook->callback;	\
			void *_callback_data = _hook->callback_data;	\
			if (_callback != NULL &&			\
			    _callback(data, _callback_data, &_result))	\
			{						\
				return __VA_ARGS__;			\
			} else {					\
				_hook = ISC_LIST_NEXT(_hook, link);	\
			}						\
		}							\
	}

#define NS_PROCESS_HOOK(table, id, data) \
	_NS_PROCESS_HOOK(table, id, data, _result)
#define NS_PROCESS_HOOK_VOID(table, id, data) \
	_NS_PROCESS_HOOK(table, id, data)

isc_result_t
ns_hookmodule_load(const char *libname, const char *parameters,
		   const char *file, unsigned long line, isc_mem_t *mctx);
void
ns_hookmodule_unload(bool exiting);

void
ns_hook_add(ns_hooktable_t *hooktable, ns_hookpoint_t hookpoint,
	    ns_hook_t *hook);
/*%
 * Append hook function 'hook' to the list of hooks at 'hookpoint' in
 * 'hooktable'.  If 'hooktable' is NULL, the global hook table
 * ns__hook_table is used.
 *
 * Requires:
 *\li 'hook' is not NULL
 *
 *\li 'hookpoint' is less than NS_QUERY_HOOKS_COUNT
 *
 */

ns_hooktable_t *
ns_hooktable_save(void);
/*%
 * Returns a pointer to the current global hook table so it can
 * be restored after replacing it.
 */

void
ns_hooktable_reset(ns_hooktable_t *hooktable);
/*%
 * Set the global hooks table pointer to 'hooktable'.
 *
 * If 'hooktable' is NULL, restores the default global hook table.
 */

void
ns_hooktable_init(ns_hooktable_t *hooktable);
/*%
 * Initialize a hook table. If 'hooktable' is NULL, initialize
 * the global hooktable ns__hook_table.
 */

#endif /* NS_HOOKS_H */
