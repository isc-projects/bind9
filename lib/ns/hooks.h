/*
 * Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef NS_HOOKS_H
#define NS_HOOKS_H 1

#ifdef NS_HOOKS_ENABLE

/*! \file */

#include <isc/result.h>

/*
 * Hooks provide a way of running a callback function once a certain place in
 * code is reached.  Current use is limited to libns unit tests and thus:
 *
 *   - hook-related types and macros are not placed in libns header files,
 *   - hook-related code is compiled away unless --enable-developer is used,
 *   - hook-related macro names are prefixed with "NS_".
 *
 * However, the implementation is pretty generic and could be repurposed for
 * general use, e.g. as part of libisc, after some further customization.
 *
 * Hooks are created by inserting a macro into any function returning
 * isc_result_t (NS_PROCESS_HOOK()) or void (NS_PROCESS_HOOK_VOID()).  Each
 * hook has an identifier, which is an integer that is an index into the hook
 * table.  In an attempt to keep things as simple as possible, current
 * implementation:
 *
 *   - uses hook tables which are statically-sized arrays only allowing a
 *     single callback to be invoked for each hook identifier,
 *   - only supports replacing whole hook tables.
 *
 * Hook callbacks are functions which:
 *
 *   - return a boolean value; if ISC_TRUE is returned by the callback, the
 *     function into which the hook is inserted will return at hook insertion
 *     point; if ISC_FALSE is returned by the callback, execution of the
 *     function into which the hook is inserted continues normally,
 *
 *   - accept three pointers as arguments:
 *
 *       - a pointer specified by the hook itself,
 *       - a pointer specified upon inserting the callback into the hook table,
 *       - a pointer to isc_result_t which will be returned by the function
 *         into which the hook is inserted if the callback returns ISC_TRUE.
 *
 * In order for a hook callback to be called for a given hook, a pointer to
 * that callback (along with an optional pointer to callback-specific data) has
 * to be inserted into the hook table entry for that hook.
 *
 * Consider the following sample code:
 *
 * ----------------------------------------------------------------------------
 * const ns_hook_t *foo_hook_table = NULL;
 *
 * isc_result_t
 * foo_bar(void) {
 *     int val = 42;
 *     ...
 *     NS_PROCESS_HOOK(foo_hook_table, FOO_EXTRACT_VAL, &val);
 *     ...
 *     printf("This message may not be printed due to use of hooks.");
 *
 *     return (ISC_R_SUCCESS);
 * }
 *
 * isc_boolean_t
 * cause_failure(void *hook_data, void *callback_data, isc_result_t *resultp) {
 *     ...
 *     *resultp = ISC_R_FAILURE;
 *
 *     return (ISC_TRUE);
 * }
 *
 * void
 * test_foo_bar(void) {
 *     isc_boolean_t foo_bar_called = ISC_FALSE;
 *     const ns_hook_t my_hooks[FOO_HOOKS_COUNT] = {
 *         [FOO_EXTRACT_VAL] = {
 *             .callback = cause_failure,
 *             .callback_data = &foo_bar_called,
 *         },
 *     };
 *
 *     foo_hook_table = my_hooks;
 *
 *     foo_bar();
 * }
 * ----------------------------------------------------------------------------
 *
 * When test_foo_bar() is called, the hook table is first replaced.  Then
 * foo_bar() gets invoked.  Once execution reaches the insertion point for hook
 * FOO_EXTRACT_VAL, cause_failure() will be called with &val as hook_data and
 * &foo_bar_called as callback_data.  It can do whatever it pleases with these
 * two values.  Eventually, cause_failure() sets *resultp to ISC_R_FAILURE and
 * returns ISC_TRUE, which causes foo_bar() to return ISC_R_FAILURE and never
 * execute the printf() call below hook insertion point.
 */

enum {
	NS_QUERY_SETUP_QCTX_INITIALIZED,
	NS_QUERY_LOOKUP_BEGIN,
	NS_QUERY_DONE_BEGIN,
	NS_QUERY_HOOKS_COUNT
};

typedef isc_boolean_t
(*ns_hook_cb_t)(void *hook_data, void *callback_data, isc_result_t *resultp);

typedef struct ns_hook {
	ns_hook_cb_t callback;
	void *callback_data;
} ns_hook_t;

#define _NS_PROCESS_HOOK(table, id, data, ...)				\
	if (table != NULL) {						\
		ns_hook_cb_t _callback = table[id].callback;		\
		void *_callback_data = table[id].callback_data;		\
		isc_result_t _result;					\
									\
		if (_callback != NULL &&				\
		    _callback(data, _callback_data, &_result)) {	\
			return __VA_ARGS__;				\
		}							\
	}

#define NS_PROCESS_HOOK(table, id, data) \
	_NS_PROCESS_HOOK(table, id, data, _result)

#define NS_PROCESS_HOOK_VOID(table, id, data) \
	_NS_PROCESS_HOOK(table, id, data)

LIBNS_EXTERNAL_DATA extern const ns_hook_t *ns__hook_table;

#endif /* NS_HOOKS_ENABLE */
#endif /* NS_HOOKS_H */
