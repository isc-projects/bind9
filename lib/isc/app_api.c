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


#include <config.h>

#include <stdbool.h>
#include <unistd.h>

#include <isc/app.h>
#include <isc/magic.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/util.h>

static isc_mutex_t createlock;
static isc_once_t once = ISC_ONCE_INIT;
static isc_appctxcreatefunc_t appctx_createfunc = NULL;
static bool is_running = false;

#define ISCAPI_APPMETHODS_VALID(m) ISC_MAGIC_VALID(m, ISCAPI_APPMETHODS_MAGIC)

static void
initialize(void) {
	RUNTIME_CHECK(isc_mutex_init(&createlock) == ISC_R_SUCCESS);
}

isc_result_t
isc_app_register(isc_appctxcreatefunc_t createfunc) {
	isc_result_t result = ISC_R_SUCCESS;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);

	LOCK(&createlock);
	if (appctx_createfunc == NULL)
		appctx_createfunc = createfunc;
	else
		result = ISC_R_EXISTS;
	UNLOCK(&createlock);

	return (result);
}

isc_result_t
isc_appctx_create(isc_mem_t *mctx, isc_appctx_t **ctxp) {
	return (isc__appctx_create(mctx, ctxp));
}

void
isc_appctx_destroy(isc_appctx_t **ctxp) {
	REQUIRE(ctxp != NULL && ISCAPI_APPCTX_VALID(*ctxp));

	isc__appctx_destroy(ctxp);
	ENSURE(*ctxp == NULL);
}

isc_result_t
isc_app_ctxstart(isc_appctx_t *ctx) {
	REQUIRE(ISCAPI_APPCTX_VALID(ctx));

	return (isc__app_ctxstart(ctx));
}

isc_result_t
isc_app_ctxrun(isc_appctx_t *ctx) {
	REQUIRE(ISCAPI_APPCTX_VALID(ctx));

	return (isc__app_ctxrun(ctx));
}

isc_result_t
isc_app_ctxonrun(isc_appctx_t *ctx, isc_mem_t *mctx,
		 isc_task_t *task, isc_taskaction_t action,
		 void *arg)
{
	REQUIRE(ISCAPI_APPCTX_VALID(ctx));

	return (isc__app_ctxonrun(ctx, mctx, task, action, arg));
}

isc_result_t
isc_app_ctxsuspend(isc_appctx_t *ctx) {
	REQUIRE(ISCAPI_APPCTX_VALID(ctx));

	return (isc__app_ctxsuspend(ctx));
}

isc_result_t
isc_app_ctxshutdown(isc_appctx_t *ctx) {
	REQUIRE(ISCAPI_APPCTX_VALID(ctx));

	return (isc__app_ctxshutdown(ctx));
}

void
isc_app_ctxfinish(isc_appctx_t *ctx) {
	REQUIRE(ISCAPI_APPCTX_VALID(ctx));

	isc__app_ctxfinish(ctx);
}

void
isc_appctx_settaskmgr(isc_appctx_t *ctx, isc_taskmgr_t *taskmgr) {
	REQUIRE(ISCAPI_APPCTX_VALID(ctx));
	REQUIRE(taskmgr != NULL);

	isc__appctx_settaskmgr(ctx, taskmgr);
}

void
isc_appctx_setsocketmgr(isc_appctx_t *ctx, isc_socketmgr_t *socketmgr) {
	REQUIRE(ISCAPI_APPCTX_VALID(ctx));
	REQUIRE(socketmgr != NULL);

	isc__appctx_setsocketmgr(ctx, socketmgr);
}

void
isc_appctx_settimermgr(isc_appctx_t *ctx, isc_timermgr_t *timermgr) {
	REQUIRE(ISCAPI_APPCTX_VALID(ctx));
	REQUIRE(timermgr != NULL);

	isc__appctx_settimermgr(ctx, timermgr);
}

isc_result_t
isc_app_start(void) {
	return (isc__app_start());
}

isc_result_t
isc_app_onrun(isc_mem_t *mctx, isc_task_t *task,
	       isc_taskaction_t action, void *arg)
{
	return (isc__app_onrun(mctx, task, action, arg));
}

isc_result_t
isc_app_run() {
	isc_result_t result;

	is_running = ISC_TRUE;
	result = isc__app_run();
	is_running = ISC_FALSE;

	return (result);
}

bool
isc_app_isrunning() {
	return (is_running);
}

isc_result_t
isc_app_shutdown(void) {
	return (isc__app_shutdown());
}

isc_result_t
isc_app_reload(void) {
	return (isc__app_reload());
}

void
isc_app_finish(void) {
	isc__app_finish();
}

void
isc_app_block(void) {
	isc__app_block();
}

void
isc_app_unblock(void) {
	isc__app_unblock();
}
