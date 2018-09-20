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

/*! \file */

#include <config.h>

#include <string.h>

#if HAVE_DLFCN_H
#include <dlfcn.h>
#elif _WIN32
#include <windows.h>
#endif

#include <isc/list.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/platform.h>
#include <isc/util.h>
#include <isc/types.h>

#include <ns/hooks.h>
#include <ns/log.h>
#include <ns/query.h>

#define CHECK(op)						\
	do {							\
		result = (op);					\
		if (result != ISC_R_SUCCESS) {			\
			goto cleanup;				\
		}						\
	} while (0)

typedef struct ns_hook_module ns_hook_module_t;
struct ns_hook_module {
	isc_mem_t			*mctx;
	void				*handle;
	char				*modpath;
	ns_hook_register_t		*register_func;
	ns_hook_destroy_t		*destroy_func;
	void				*inst;
	LINK(ns_hook_module_t)		link;
};

static ns_hooklist_t default_hooktable[NS_HOOKPOINTS_COUNT];
LIBNS_EXTERNAL_DATA ns_hooktable_t *ns__hook_table = &default_hooktable;

/*
 * List of hook modules.
 *
 * These are stored here so they can be cleaned up on shutdown.
 * (The order in which they are stored is not important.)
 */
static ISC_LIST(ns_hook_module_t) hook_modules;
static bool hook_modules_initialized = false;

#if HAVE_DLFCN_H && HAVE_DLOPEN
static isc_result_t
load_symbol(void *handle, const char *modpath,
	    const char *symbol_name, void **symbolp)
{
	void *symbol = NULL;

	REQUIRE(handle != NULL);
	REQUIRE(symbolp != NULL && *symbolp == NULL);

	/*
	 * Clear any pre-existing error conditions before running dlsym().
	 * (In this case, we expect dlsym() to return non-NULL values
	 * and will always return an error if it returns NULL, but
	 * this ensures that we'll report the correct error condition
	 * if there is one.)
	 */
	dlerror();
	symbol = dlsym(handle, symbol_name);
	if (symbol == NULL) {
		const char *errmsg = dlerror();
		if (errmsg == NULL) {
			errmsg = "returned function pointer is NULL";
		}
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "failed to look up symbol %s in "
			      "hook module '%s': %s",
			      symbol_name, modpath, errmsg);
		return (ISC_R_FAILURE);
	}

	*symbolp = symbol;

	return (ISC_R_SUCCESS);
}

static isc_result_t
load_library(isc_mem_t *mctx, const char *modpath, ns_hook_module_t **hmodp) {
	isc_result_t result;
	void *handle = NULL;
	ns_hook_module_t *hmod = NULL;
	ns_hook_register_t *register_func = NULL;
	ns_hook_destroy_t *destroy_func = NULL;
	ns_hook_version_t *version_func = NULL;
	int version, flags;

	REQUIRE(hmodp != NULL && *hmodp == NULL);

	flags = RTLD_NOW | RTLD_LOCAL;
#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	handle = dlopen(modpath, flags);
	if (handle == NULL) {
		const char *errmsg = dlerror();
		if (errmsg == NULL) {
			errmsg = "unknown error";
		}
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "failed to dlopen() hook module '%s': %s",
			      modpath, errmsg);
		return (ISC_R_FAILURE);
	}

	CHECK(load_symbol(handle, modpath, "hook_version",
			  (void **)&version_func));

	version = version_func();
	if (version < (NS_HOOK_VERSION - NS_HOOK_AGE) ||
	    version > NS_HOOK_VERSION)
	{
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "hook API version mismatch: %d/%d",
			      version, NS_HOOK_VERSION);
		CHECK(ISC_R_FAILURE);
	}

	CHECK(load_symbol(handle, modpath, "hook_register",
			  (void **)&register_func));
	CHECK(load_symbol(handle, modpath, "hook_destroy",
			  (void **)&destroy_func));

	hmod = isc_mem_get(mctx, sizeof(*hmod));
	if (hmod == NULL) {
		CHECK(ISC_R_NOMEMORY);
	}

	hmod->mctx = NULL;
	isc_mem_attach(mctx, &hmod->mctx);
	hmod->handle = handle;
	hmod->modpath = isc_mem_strdup(hmod->mctx, modpath);
	hmod->register_func = register_func;
	hmod->destroy_func = destroy_func;
	hmod->inst = NULL;

	ISC_LINK_INIT(hmod, link);

	*hmodp = hmod;
	hmod = NULL;

cleanup:
	if (result != ISC_R_SUCCESS) {
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "failed to dynamically load "
			      "module '%s': %s", modpath,
			      isc_result_totext(result));

		if (hmod != NULL) {
			isc_mem_putanddetach(&hmod->mctx, hmod, sizeof(*hmod));
		}

		if (handle != NULL) {
			(void) dlclose(handle);
		}
	}

	return (result);
}

static void
unload_library(ns_hook_module_t **hmodp) {
	ns_hook_module_t *hmod = NULL;

	REQUIRE(hmodp != NULL && *hmodp != NULL);

	hmod = *hmodp;
	*hmodp = NULL;

	if (hmod->handle != NULL) {
		(void) dlclose(hmod->handle);
	}
	if (hmod->modpath != NULL) {
		isc_mem_free(hmod->mctx, hmod->modpath);
	}

	isc_mem_putanddetach(&hmod->mctx, hmod, sizeof(*hmod));
}
#elif _WIN32
static isc_result_t
load_symbol(HMODULE handle, const char *modpath,
	    const char *symbol_name, void **symbolp)
{
	void *symbol = NULL;

	REQUIRE(handle != NULL);
	REQUIRE(symbolp != NULL && *symbolp == NULL);

	symbol = GetProcAddress(handle, symbol_name);
	if (symbol == NULL) {
		int errstatus = GetLastError();
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "failed to look up symbol %s in "
			      "module '%s': %d",
			      symbol_name, modpath, errstatus);
		return (ISC_R_FAILURE);
	}

	*symbolp = symbol;

	return (ISC_R_SUCCESS);
}

static isc_result_t
load_library(isc_mem_t *mctx, const char *modpath, ns_hook_module_t **hmodp) {
	isc_result_t result;
	HMODULE handle;
	ns_hook_module_t *hmod = NULL;
	ns_hook_register_t *register_func = NULL;
	ns_hook_destroy_t *destroy_func = NULL;
	ns_hook_version_t *version_func = NULL;
	int version;

	REQUIRE(hmodp != NULL && *hmodp == NULL);

	handle = LoadLibraryA(modpath);
	if (handle == NULL) {
		CHECK(ISC_R_FAILURE);
	}

	CHECK(load_symbol(handle, modpath, "hook_version",
			  (void **)&version_func));

	version = version_func(NULL);
	if (version < (NS_HOOK_VERSION - NS_HOOK_AGE) ||
	    version > NS_HOOK_VERSION)
	{
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "hook API version mismatch: %d/%d",
			      version, NS_HOOK_VERSION);
		CHECK(ISC_R_FAILURE);
	}

	CHECK(load_symbol(handle, modpath, "hook_register",
			  (void **)&register_func));
	CHECK(load_symbol(handle, modpath, "hook_destroy",
			  (void **)&destroy_func));

	hmod = isc_mem_get(mctx, sizeof(*hmod));
	if (hmod == NULL) {
		CHECK(ISC_R_NOMEMORY);
	}

	hmod->mctx = NULL;
	isc_mem_attach(mctx, &hmod->mctx);
	hmod->handle = handle;
	hmod->modpath = isc_mem_strdup(hmod->mctx, modpath);
	hmod->register_func = register_func;
	hmod->destroy_func = destroy_func;
	hmod->inst = NULL;

	ISC_LINK_INIT(hmod, link);

	*hmodp = hmod;
	hmod = NULL;

cleanup:
	if (result != ISC_R_SUCCESS) {
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "failed to dynamically load "
			      "hook module '%s': %d (%s)", modpath,
			      GetLastError(), isc_result_totext(result));

		if (hmod != NULL) {
			isc_mem_putanddetach(&hmod->mctx, hmod, sizeof(*hmod));
		}

		if (handle != NULL) {
			FreeLibrary(handle);
		}
	}

	return (result);
}

static void
unload_library(ns_hook_module_t **hmodp) {
	ns_hook_module_t *hmod = NULL;

	REQUIRE(hmodp != NULL && *hmodp != NULL);

	hmod = *hmodp;
	*hmodp = NULL;

	if (hmod->handle != NULL) {
		FreeLibrary(hmod->handle);
	}

	if (hmod->modpath != NULL) {
		isc_mem_free(hmod->mctx, hmod->modpath);
	}

	isc_mem_putanddetach(&hmod->mctx, hmod, sizeof(*hmod));
}
#else	/* HAVE_DLFCN_H || _WIN32 */
static isc_result_t
load_library(isc_mem_t *mctx, const char *modpath, ns_hook_module_t **hmodp) {
	UNUSED(mctx);
	UNUSED(modpath);
	UNUSED(hmodp);

	isc_log_write(ns_lctx, NS_LOGCATEGORY_DATABASE,
		      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
		      "hook module support is not implemented");

	return (ISC_R_NOTIMPLEMENTED);
}

static void
unload_library(ns_hook_module_t **hmodp) {
	UNUSED(hmodp);
}
#endif	/* HAVE_DLFCN_H */

isc_result_t
ns_hookmodule_load(const char *modpath, const char *parameters,
		   const char *cfg_file, unsigned long cfg_line,
		   const void *cfg, void *actx,
		   ns_hookctx_t *hctx, ns_hooktable_t *hooktable)
{
	isc_result_t result;
	ns_hook_module_t *hmod = NULL;

	REQUIRE(hook_modules_initialized);
	REQUIRE(NS_HOOKCTX_VALID(hctx));
	REQUIRE(hooktable != NULL);

	isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "loading module '%s'", modpath);

	CHECK(load_library(hctx->mctx, modpath, &hmod));
	CHECK(hmod->register_func(parameters, cfg_file, cfg_line,
				  cfg, actx, hctx, hooktable, &hmod->inst));

	ISC_LIST_APPEND(hook_modules, hmod, link);

cleanup:
	if (result != ISC_R_SUCCESS && hmod != NULL) {
		unload_library(&hmod);
	}

	return (result);
}

void
ns_hookmodule_unload_all(void) {
	ns_hook_module_t *hmod = NULL, *prev = NULL;

	if (!hook_modules_initialized) {
		return;
	}

	hmod = ISC_LIST_TAIL(hook_modules);
	while (hmod != NULL) {
		prev = ISC_LIST_PREV(hmod, link);
		ISC_LIST_UNLINK(hook_modules, hmod, link);
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
			      "unloading module '%s'", hmod->modpath);
		hmod->destroy_func(&hmod->inst);
		ENSURE(hmod->inst == NULL);
		unload_library(&hmod);
		hmod = prev;
	}
}

isc_result_t
ns_hook_createctx(isc_mem_t *mctx, const void *hashinit, ns_hookctx_t **hctxp) {
	ns_hookctx_t *hctx = NULL;

	REQUIRE(hctxp != NULL && *hctxp == NULL);

	hctx = isc_mem_get(mctx, sizeof(*hctx));
	if (hctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	memset(hctx, 0, sizeof(*hctx));
	hctx->hashinit = hashinit;
	hctx->lctx = ns_lctx;
	hctx->refvar = &isc_bind9;

	isc_mem_attach(mctx, &hctx->mctx);
	hctx->magic = NS_HOOKCTX_MAGIC;

	*hctxp = hctx;

	return (ISC_R_SUCCESS);
}

void
ns_hook_destroyctx(ns_hookctx_t **hctxp) {
	ns_hookctx_t *hctx = NULL;

	REQUIRE(hctxp != NULL && NS_HOOKCTX_VALID(*hctxp));

	hctx = *hctxp;
	*hctxp = NULL;

	hctx->magic = 0;

	isc_mem_putanddetach(&hctx->mctx, hctx, sizeof(*hctx));
}

void
ns_hooktable_init(ns_hooktable_t *hooktable) {
	int i;

	if (!hook_modules_initialized) {
		ISC_LIST_INIT(hook_modules);
		hook_modules_initialized = true;
	}

	for (i = 0; i < NS_HOOKPOINTS_COUNT; i++) {
		ISC_LIST_INIT((*hooktable)[i]);
	}
}

isc_result_t
ns_hooktable_create(isc_mem_t *mctx, ns_hooktable_t **tablep) {
	ns_hooktable_t *hooktable = NULL;

	REQUIRE(tablep != NULL && *tablep == NULL);

	hooktable = isc_mem_get(mctx, sizeof(*hooktable));
	if (hooktable == NULL) {
		return (ISC_R_NOMEMORY);
	}

	ns_hooktable_init(hooktable);

	*tablep = hooktable;

	return (ISC_R_SUCCESS);
}

void
ns_hooktable_free(isc_mem_t *mctx, void **tablep) {
	ns_hooktable_t *table = NULL;
	ns_hook_t *hook = NULL, *next = NULL;
	int i = 0;

	REQUIRE(tablep != NULL && *tablep != NULL);

	table = *tablep;
	*tablep = NULL;

	for (i = 0; i < NS_HOOKPOINTS_COUNT; i++) {
		for (hook = ISC_LIST_HEAD((*table)[i]);
		     hook != NULL;
		     hook = next)
		{
			next = ISC_LIST_NEXT(hook, link);
			ISC_LIST_UNLINK((*table)[i], hook, link);
			if (hook->mctx != NULL) {
				isc_mem_putanddetach(&hook->mctx,
						     hook, sizeof(*hook));
			}
		}
	}

	isc_mem_put(mctx, table, sizeof(*table));
}

void
ns_hook_add(ns_hooktable_t *hooktable, isc_mem_t *mctx,
	    ns_hookpoint_t hookpoint, ns_hook_t *hook)
{
	ns_hook_t *copy = NULL;

	REQUIRE(hookpoint < NS_HOOKPOINTS_COUNT);
	REQUIRE(hook != NULL);
	REQUIRE(hook->mctx == NULL);

	if (hooktable == NULL) {
		hooktable = ns__hook_table;
	}

	if (mctx == NULL) {
		copy = hook;
	} else {
		copy = isc_mem_get(mctx, sizeof(*copy));
		memset(copy, 0, sizeof(*copy));

		copy->action = hook->action;
		copy->action_data = hook->action_data;
		isc_mem_attach(mctx, &copy->mctx);
	}

	ISC_LINK_INIT(copy, link);
	ISC_LIST_APPEND((*hooktable)[hookpoint], copy, link);
}
