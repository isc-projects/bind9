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

#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/once.h>
#include <isc/util.h>

#include <ns/hooks.h>
#include <ns/log.h>

#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto cleanup;	\
	} while (0)

typedef struct ns_hook_module ns_hook_module_t;
struct ns_hook_module {
	isc_mem_t			*mctx;
	void				*handle;
	ns_hook_register_t		*register_func;
	ns_hook_destroy_t		*destroy_func;
	void				*inst;
	LINK(ns_hook_module_t)		link;
};

static ns_hooklist_t hooktab[NS_QUERY_HOOKS_COUNT];
LIBNS_EXTERNAL_DATA ns_hooktable_t *ns__hook_table = &hooktab;

/*
 * List of hook modules. Locked by hook_lock.
 *
 * These are stored here so they can be cleaned up on shutdown.
 * (The order in which they are stored is not important.)
 */
static LIST(ns_hook_module_t) hook_modules;

/* Locks ns_hook_modules. */
static isc_mutex_t hook_lock;
static isc_once_t once = ISC_ONCE_INIT;

static void
init_modules(void) {
	RUNTIME_CHECK(isc_mutex_init(&hook_lock) == ISC_R_SUCCESS);
	INIT_LIST(hook_modules);
}

#if HAVE_DLFCN_H && HAVE_DLOPEN
static isc_result_t
load_symbol(void *handle, const char *filename,
	    const char *symbol_name, void **symbolp)
{
	const char *errmsg;
	void *symbol;

	REQUIRE(handle != NULL);
	REQUIRE(symbolp != NULL && *symbolp == NULL);

	symbol = dlsym(handle, symbol_name);
	if (symbol == NULL) {
		errmsg = dlerror();
		if (errmsg == NULL) {
			errmsg = "returned function pointer is NULL";
		}
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "failed to look upsymbol %s in "
			      "hook module '%s': %s",
			      symbol_name, filename, errmsg);
		return (ISC_R_FAILURE);
	}
	dlerror();

	*symbolp = symbol;

	return (ISC_R_SUCCESS);
}

static isc_result_t
load_library(isc_mem_t *mctx, const char *filename, ns_hook_module_t **impp) {
	isc_result_t result;
	void *handle = NULL;
	ns_hook_module_t *imp = NULL;
	ns_hook_register_t *register_func = NULL;
	ns_hook_destroy_t *destroy_func = NULL;
	ns_hook_version_t *version_func = NULL;
	int version, flags;

	REQUIRE(impp != NULL && *impp == NULL);

	isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "loading hook module '%s'", filename);

	flags = RTLD_NOW|RTLD_LOCAL;
#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	handle = dlopen(filename, flags);
	if (handle == NULL) {
		CHECK(ISC_R_FAILURE);
	}

	/* Clear dlerror */
	dlerror();

	CHECK(load_symbol(handle, filename, "hook_version",
			  (void **)&version_func));

	version = version_func(NULL);
	if (version < (NS_HOOK_VERSION - NS_HOOK_AGE) ||
	    version > NS_HOOK_VERSION)
	{
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "driver API version mismatch: %d/%d",
			      version, NS_HOOK_VERSION);
		CHECK(ISC_R_FAILURE);
	}

	CHECK(load_symbol(handle, filename, "hook_register",
			  (void **)&register_func));
	CHECK(load_symbol(handle, filename, "hook_destroy",
			  (void **)&destroy_func));

	imp = isc_mem_get(mctx, sizeof(ns_hook_module_t));
	if (imp == NULL) {
		CHECK(ISC_R_NOMEMORY);
	}

	imp->mctx = NULL;
	isc_mem_attach(mctx, &imp->mctx);
	imp->handle = handle;
	imp->register_func = register_func;
	imp->destroy_func = destroy_func;

	imp->inst = NULL;
	INIT_LINK(imp, link);

	*impp = imp;
	imp = NULL;

cleanup:
	if (result != ISC_R_SUCCESS) {
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "failed to dynamically load "
			      "hook module '%s': %s (%s)", filename,
			      dlerror(), isc_result_totext(result));
	}
	if (imp != NULL) {
		isc_mem_putanddetach(&imp->mctx, imp,
				     sizeof(ns_hook_module_t));
	}
	if (result != ISC_R_SUCCESS && handle != NULL) {
		dlclose(handle);
	}

	return (result);
}

static void
unload_library(ns_hook_module_t **impp) {
	ns_hook_module_t *imp;

	REQUIRE(impp != NULL && *impp != NULL);

	imp = *impp;

	isc_mem_putanddetach(&imp->mctx, imp, sizeof(ns_hook_module_t));

	*impp = NULL;
}
#elif _WIN32
static isc_result_t
load_symbol(HMODULE handle, const char *filename,
	    const char *symbol_name, void **symbolp)
{
	void *symbol;

	REQUIRE(handle != NULL);
	REQUIRE(symbolp != NULL && *symbolp == NULL);

	symbol = GetProcAddress(handle, symbol_name);
	if (symbol == NULL) {
		int errstatus = GetLastError();
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "failed to look up symbol %s in "
			      "hook module '%s': %d",
			      symbol_name, filename, errstatus);
		return (ISC_R_FAILURE);
	}

	*symbolp = symbol;

	return (ISC_R_SUCCESS);
}

static isc_result_t
load_library(isc_mem_t *mctx, const char *filename, ns_hook_module_t **impp) {
	isc_result_t result;
	HMODULE handle;
	ns_hook_module_t *imp = NULL;
	ns_hook_register_t *register_func = NULL;
	ns_hook_destroy_t *destroy_func = NULL;
	ns_hook_version_t *version_func = NULL;
	int version;

	REQUIRE(impp != NULL && *impp == NULL);

	isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "loading hook module '%s'",
		      filename);

	handle = LoadLibraryA(filename);
	if (handle == NULL) {
		CHECK(ISC_R_FAILURE);
	}

	CHECK(load_symbol(handle, filename, "hook_version",
			  (void **)&version_func));

	version = version_func(NULL);
	if (version < (NS_HOOK_VERSION - NS_HOOK_AGE) ||
	    version > NS_HOOK_VERSION)
	{
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "driver API version mismatch: %d/%d",
			      version, NS_HOOK_VERSION);
		CHECK(ISC_R_FAILURE);
	}

	CHECK(load_symbol(handle, filename, "hook_register",
			  (void **)&register_func));
	CHECK(load_symbol(handle, filename, "hook_destroy",
			  (void **)&destroy_func));

	imp = isc_mem_get(mctx, sizeof(ns_hook_module_t));
	if (imp == NULL) {
		CHECK(ISC_R_NOMEMORY);
	}

	imp->mctx = NULL;
	isc_mem_attach(mctx, &imp->mctx);
	imp->handle = handle;
	imp->register_func = register_func;
	imp->destroy_func = destroy_func;

	imp->inst = NULL;
	INIT_LINK(imp, link);

	*impp = imp;
	imp = NULL;

cleanup:
	if (result != ISC_R_SUCCESS) {
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
			      "failed to dynamically load "
			      "hook module '%s': %d (%s)", filename,
			      GetLastError(), isc_result_totext(result));
	}
	if (imp != NULL) {
		isc_mem_putanddetach(&imp->mctx, imp,
				     sizeof(ns_hook_module_t));
	}
	if (result != ISC_R_SUCCESS && handle != NULL) {
		FreeLibrary(handle);
	}

	return (result);
}

static void
unload_library(ns_hook_module_t **impp) {
	ns_hook_module_t *imp;

	REQUIRE(impp != NULL && *impp != NULL);

	imp = *impp;

	isc_mem_putanddetach(&imp->mctx, imp, sizeof(ns_hook_module_t));

	*impp = NULL;
}
#else	/* HAVE_DLFCN_H || _WIN32 */
static isc_result_t
load_library(isc_mem_t *mctx, const char *filename, ns_hook_module_t **impp) {
	UNUSED(mctx);
	UNUSED(filename);
	UNUSED(impp);

	isc_log_write(ns_lctx, NS_LOGCATEGORY_DATABASE, NS_LOGMODULE_HOOKS,
		      ISC_LOG_ERROR,
		      "dynamic database support is not implemented");

	return (ISC_R_NOTIMPLEMENTED);
}

static void
unload_library(ns_hook_module_t **impp)
{
	UNUSED(impp);
}
#endif	/* HAVE_DLFCN_H */

isc_result_t
ns_hookmodule_load(const char *libname, const char *parameters,
		   const char *file, unsigned long line,
		   ns_hookctx_t *hctx, ns_hooktable_t *hooktable)
{
	isc_result_t result;
	ns_hook_module_t *implementation = NULL;

	REQUIRE(NS_HOOKCTX_VALID(hctx));

	LOCK(&hook_lock);

	CHECK(load_library(hctx->mctx, libname, &implementation));
	CHECK(implementation->register_func(parameters, file, line,
					    hctx, hooktable,
					    &implementation->inst));

	APPEND(hook_modules, implementation, link);
	result = ISC_R_SUCCESS;

cleanup:
	if (result != ISC_R_SUCCESS && implementation != NULL) {
		unload_library(&implementation);
	}

	UNLOCK(&hook_lock);
	return (result);
}

void
ns_hookmodule_cleanup(bool exiting) {
	ns_hook_module_t *elem, *prev;

	RUNTIME_CHECK(isc_once_do(&once, init_modules) == ISC_R_SUCCESS);

	LOCK(&hook_lock);
	elem = TAIL(hook_modules);
	while (elem != NULL) {
		prev = PREV(elem, link);
		UNLINK(hook_modules, elem, link);
		isc_log_write(ns_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
			      "unloading filter-aaaa module");
		elem->destroy_func(&elem->inst);
		ENSURE(elem->inst == NULL);
		unload_library(&elem);
		elem = prev;
	}
	UNLOCK(&hook_lock);

	if (exiting) {
		isc_mutex_destroy(&hook_lock);
	}
}

isc_result_t
ns_hook_createctx(isc_mem_t *mctx, const void *hashinit, ns_hookctx_t **hctxp) {
	ns_hookctx_t *hctx;

	REQUIRE(hctxp != NULL && *hctxp == NULL);

	hctx = isc_mem_get(mctx, sizeof(*hctx));
	if (hctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	memset(hctx, 0, sizeof(*hctx));
	hctx->hashinit = hashinit;
	hctx->lctx = ns_lctx;
	hctx->refvar = &isc_bind9;

	hctx->query_recurse = ns_query_recurse;
	hctx->query_done = ns_query_done;

	isc_mem_attach(mctx, &hctx->mctx);
	hctx->magic = NS_HOOKCTX_MAGIC;

	*hctxp = hctx;

	return (ISC_R_SUCCESS);
}

void
ns_hook_destroyctx(ns_hookctx_t **hctxp) {
	ns_hookctx_t *hctx;

	REQUIRE(hctxp != NULL && NS_HOOKCTX_VALID(*hctxp));

	hctx = *hctxp;
	*hctxp = NULL;

	hctx->magic = 0;

	hctx->lctx = NULL;

	isc_mem_putanddetach(&hctx->mctx, hctx, sizeof(*hctx));
}

void
ns_hooktable_init(ns_hooktable_t *hooktable) {
	int i;

	RUNTIME_CHECK(isc_once_do(&once, init_modules) == ISC_R_SUCCESS);

	for (i = 0; i < NS_QUERY_HOOKS_COUNT; i++) {
		ISC_LIST_INIT((*hooktable)[i]);
	}
}

isc_result_t
ns_hooktable_create(isc_mem_t *mctx, ns_hooktable_t **tablep) {
	ns_hooktable_t *hooktable;

	REQUIRE(tablep != NULL && *tablep == NULL);

	hooktable = isc_mem_get(mctx, sizeof(ns_hooktable_t));
	if (hooktable == NULL) {
		return (ISC_R_NOMEMORY);
	}

	ns_hooktable_init(hooktable);

	*tablep = hooktable;

	return (ISC_R_SUCCESS);
}

void
ns_hooktable_free(isc_mem_t *mctx, void **tablep) {
	REQUIRE(tablep != NULL && *tablep != NULL);

	isc_mem_put(mctx, *tablep, sizeof(ns_hooktable_t));
	*tablep = NULL;
}

void
ns_hook_add(ns_hooktable_t *hooktable, ns_hookpoint_t hookpoint,
	    ns_hook_t *hook)
{
	REQUIRE(hookpoint < NS_QUERY_HOOKS_COUNT);
	REQUIRE(hook != NULL);

	if (hooktable == NULL) {
		hooktable = ns__hook_table;
	}

	ISC_LINK_INIT(hook, link);
	ISC_LIST_APPEND((*hooktable)[hookpoint], hook, link);
}
