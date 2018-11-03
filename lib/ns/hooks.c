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

#include <dns/view.h>

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

struct ns_module {
       isc_mem_t		*mctx;
       void			*handle;
       void			*inst;
       char			*modpath;
       ns_hook_check_t		*check_func;
       ns_hook_register_t	*register_func;
       ns_hook_destroy_t	*destroy_func;
       LINK(ns_module_t)	link;
};

static ns_hooklist_t default_hooktable[NS_HOOKPOINTS_COUNT];
LIBNS_EXTERNAL_DATA ns_hooktable_t *ns__hook_table = &default_hooktable;

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
load_library(isc_mem_t *mctx, const char *modpath, ns_module_t **hmodp) {
	isc_result_t result;
	void *handle = NULL;
	ns_module_t *hmod = NULL;
	ns_hook_check_t *check_func = NULL;
	ns_hook_register_t *register_func = NULL;
	ns_hook_destroy_t *destroy_func = NULL;
	ns_hook_version_t *version_func = NULL;
	int version, flags;

	REQUIRE(hmodp != NULL && *hmodp == NULL);

	flags = RTLD_LAZY | RTLD_LOCAL;
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

	CHECK(load_symbol(handle, modpath, "hook_check",
			  (void **)&check_func));
	CHECK(load_symbol(handle, modpath, "hook_register",
			  (void **)&register_func));
	CHECK(load_symbol(handle, modpath, "hook_destroy",
			  (void **)&destroy_func));

	hmod = isc_mem_get(mctx, sizeof(*hmod));
	memset(hmod, 0, sizeof(*hmod));
	isc_mem_attach(mctx, &hmod->mctx);
	hmod->handle = handle;
	hmod->modpath = isc_mem_strdup(hmod->mctx, modpath);
	hmod->check_func = check_func;
	hmod->register_func = register_func;
	hmod->destroy_func = destroy_func;

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
unload_library(ns_module_t **hmodp) {
	ns_module_t *hmod = NULL;

	REQUIRE(hmodp != NULL && *hmodp != NULL);

	hmod = *hmodp;
	*hmodp = NULL;

	isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "unloading module '%s'", hmod->modpath);

	if (hmod->inst != NULL) {
		hmod->destroy_func(&hmod->inst);
	}
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
load_library(isc_mem_t *mctx, const char *modpath, ns_module_t **hmodp) {
	isc_result_t result;
	HMODULE handle;
	ns_module_t *hmod = NULL;
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
	memset(hmod, 0, sizeof(*hmod));
	isc_mem_attach(mctx, &hmod->mctx);
	hmod->handle = handle;
	hmod->modpath = isc_mem_strdup(hmod->mctx, modpath);
	hmod->register_func = register_func;
	hmod->destroy_func = destroy_func;

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
unload_library(ns_module_t **hmodp) {
	ns_module_t *hmod = NULL;

	REQUIRE(hmodp != NULL && *hmodp != NULL);

	hmod = *hmodp;
	*hmodp = NULL;

	isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "unloading module '%s'", hmod->modpath);

	if (hmod->inst != NULL) {
		hmod->destroy_func(&hmod->inst);
	}
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
load_library(isc_mem_t *mctx, const char *modpath, ns_module_t **hmodp) {
	UNUSED(mctx);
	UNUSED(modpath);
	UNUSED(hmodp);

	isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
		      "hook module support is not implemented");

	return (ISC_R_NOTIMPLEMENTED);
}

static void
unload_library(ns_module_t **hmodp) {
	UNUSED(hmodp);
}
#endif	/* HAVE_DLFCN_H */

isc_result_t
ns_module_load(const char *modpath, const char *parameters,
	       const char *cfg_file, unsigned long cfg_line,
	       const void *cfg, void *actx, ns_hookctx_t *hctx,
	       ns_modlist_t *modlist, ns_hooktable_t *hooktable)
{
	isc_result_t result;
	ns_module_t *hmod = NULL;

	REQUIRE(NS_HOOKCTX_VALID(hctx));
	REQUIRE(modlist != NULL);
	REQUIRE(hooktable != NULL);

	isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "loading module '%s'", modpath);

	CHECK(load_library(hctx->mctx, modpath, &hmod));

	isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "registering module '%s'", modpath);

	CHECK(hmod->register_func(parameters, cfg_file, cfg_line,
				  cfg, actx, hctx, hooktable, &hmod->inst));

	ISC_LIST_APPEND(*modlist, hmod, link);

cleanup:
	if (result != ISC_R_SUCCESS && hmod != NULL) {
		unload_library(&hmod);
	}

	return (result);
}

isc_result_t
ns_module_check(const char *modpath, const char *parameters,
		const char *cfg_file, unsigned long cfg_line,
		const void *cfg, isc_mem_t *mctx, isc_log_t *lctx, void *actx)
{
	isc_result_t result;
	ns_module_t *hmod = NULL;

	CHECK(load_library(mctx, modpath, &hmod));

	result = hmod->check_func(parameters, cfg_file, cfg_line,
				  cfg, mctx, lctx, actx);

cleanup:
	if (hmod != NULL) {
		unload_library(&hmod);
	}

	return (result);
}

isc_result_t
ns_hook_createctx(isc_mem_t *mctx, dns_view_t *view, ns_hookctx_t **hctxp) {
	ns_hookctx_t *hctx = NULL;

	REQUIRE(hctxp != NULL && *hctxp == NULL);

	hctx = isc_mem_get(mctx, sizeof(*hctx));
	memset(hctx, 0, sizeof(*hctx));
	hctx->lctx = ns_lctx;

	dns_view_attach(view, &hctx->view);

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

	dns_view_detach(&hctx->view);
	isc_mem_putanddetach(&hctx->mctx, hctx, sizeof(*hctx));
}

void
ns_hooktable_init(ns_hooktable_t *hooktable) {
	int i;

	for (i = 0; i < NS_HOOKPOINTS_COUNT; i++) {
		ISC_LIST_INIT((*hooktable)[i]);
	}
}

isc_result_t
ns_hooktable_create(isc_mem_t *mctx, ns_hooktable_t **tablep) {
	ns_hooktable_t *hooktable = NULL;

	REQUIRE(tablep != NULL && *tablep == NULL);

	hooktable = isc_mem_get(mctx, sizeof(*hooktable));

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
	    ns_hookpoint_t hookpoint, const ns_hook_t *hook)
{
	ns_hook_t *copy = NULL;

	REQUIRE(hooktable != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(hookpoint < NS_HOOKPOINTS_COUNT);
	REQUIRE(hook != NULL);

	copy = isc_mem_get(mctx, sizeof(*copy));
	memset(copy, 0, sizeof(*copy));

	copy->action = hook->action;
	copy->action_data = hook->action_data;
	isc_mem_attach(mctx, &copy->mctx);

	ISC_LINK_INIT(copy, link);
	ISC_LIST_APPEND((*hooktable)[hookpoint], copy, link);
}

void
ns_modlist_create(isc_mem_t *mctx, ns_modlist_t **listp) {
	ns_modlist_t *modlist = NULL;

	REQUIRE(listp != NULL && *listp == NULL);

	modlist = isc_mem_get(mctx, sizeof(*modlist));
	memset(modlist, 0, sizeof(*modlist));
	ISC_LIST_INIT(*modlist);

	*listp = modlist;
}

void
ns_modlist_free(isc_mem_t *mctx, void **listp) {
	ns_modlist_t *list = NULL;
	ns_module_t *hmod = NULL, *next = NULL;

	REQUIRE(listp != NULL && *listp != NULL);

	list = *listp;
	*listp = NULL;

	for (hmod = ISC_LIST_HEAD(*list);
	     hmod != NULL;
	     hmod = next)
	{
		next = ISC_LIST_NEXT(hmod, link);
		ISC_LIST_UNLINK(*list, hmod, link);
		unload_library(&hmod);
	}

	isc_mem_put(mctx, list, sizeof(*list));
}
