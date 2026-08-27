/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/tid.h>
#include <isc/time.h>
#include <isc/tls.h>
#include <isc/types.h>

/*! \file isc/quic.h */

/**
 * \brief
 * Minimum allowed length of a CID.
 *
 * Specified in RFC9000, Section 17.2.
 */
#define ISC_QUIC_CID_MIN_LENGTH 1

/**
 * \brief
 * Maximum allowed length of a CID.
 *
 * Specified in RFC9000, Section 17.2.
 */
#define ISC_QUIC_CID_MAX_LENGTH 20

/**
 * \brief
 * Length of the stateless reset token.
 *
 * Specified in RFC9000, Section 10.3.
 */
#define ISC_QUIC_STATELESS_TOKEN_LENGTH 16

/**
 * \brief
 * Thread-safe data structure for associating CID's and stateless reset tokens
 * to QUIC connections.
 */
typedef struct isc_quic_router isc_quic_router_t;

typedef enum isc_quic_version {
	/** Invalid QUIC version */
	ISC_QUIC_VERSION_INVALID = 0,

	/** Unknown QUIC version */
	ISC_QUIC_VERSION_UNKNOWN = 1,

	/** RFC9000 */
	ISC_QUIC_VERSION_V1 = 2,

	/** RFC9369 */
	ISC_QUIC_VERSION_V2 = 3,

	ISC_QUIC_VERSION__MAX = 4,
} isc_quic_version_t;

typedef enum isc_quic_application_error_kind {
	/**
	 * \brief
	 * Indeterminate application error status.
	 *
	 * It is safe to trigger an contract failure upon receiving this value.
	 */
	ISC_QUIC_APPLICATION_ERROR_INVALID = 0,

	/**
	 * \brief
	 * No application error code is set.
	 */
	ISC_QUIC_APPLICATION_ERROR_NONE = 1,

	/**
	 * \brief
	 * The linked ngtcp2 is too old to determine which side has set the
	 * application error code.
	 */
	ISC_QUIC_APPLICATION_ERROR_UNKNOWN = 2,

	ISC_QUIC_APPLICATION_ERROR_RX_ONLY = 3,
	ISC_QUIC_APPLICATION_ERROR_TX_ONLY = 4,
	ISC_QUIC_APPLICATION_ERROR_RX_AND_TX = 5,
	ISC_QUIC_APPLICATION_ERROR__MAX = 6,
} isc_quic_application_error_kind_t;

/**
 * \brief
 * User-specified callbacks
 *
 * All callbacks are optional.
 */
struct isc_quic_conn_callbacks {
	/**
	 * \brief
	 * Callback function for when handshake has been completed
	 */
	void (*handshake_completed)(void *cbarg);

	/**
	 * \brief
	 * Callback function for when the remote endpoint has opened a new
	 * stream.
	 */
	isc_result_t (*stream_opened)(isc_quic_conn_t *conn, void *cbarg,
				      int64_t stream_id);

	/**
	 * \brief
	 * Callback function for when a stream has been closed.
	 *
	 * If the application error kind is unknown, both RX and TX application
	 * errors codes will be set as the unknown side's error code.
	 *
	 * Returning anything other than `ISC_R_SUCCESS` will cause the
	 * connection to fail and require closing.
	 */
	isc_result_t (*stream_closed)(isc_quic_conn_t *conn, void *cbarg,
				      int64_t stream_id,
				      isc_quic_application_error_kind_t kind,
				      uint64_t rx_application_error_code,
				      uint64_t tx_application_error_code);

	/**
	 * \brief
	 * Callback function for when there is data to be read in a stream.
	 *
	 * Called by isc_quic_conn_push_packet when there is data to be read
	 * in a stream.
	 *
	 * Returning anything other than `ISC_R_SUCCESS` will cause the
	 * connection to fail and require closing.
	 */
	isc_result_t (*data_read)(isc_quic_conn_t *conn, void *cbarg,
				  isc_quic_stream_data_info_t info,
				  isc_constregion_t	      data);
};

struct isc_quic_stream_data_info {
	/**
	 * \brief
	 * True if this is the final packet that will be received from this
	 * stream.
	 */
	bool final;

	/**
	 * \brief
	 * True if the data is trasmitted during 0-RTT.
	 */
	bool zerortt;

	/**
	 * \brief
	 * Stream ID of received data.
	 */
	int64_t stream_id;
};

/**
 * \brief
 * Connection independent QUIC connection options of an endpoint.
 */
struct isc_quic_conn_options {
	/**
	 * \brief
	 * TLS context used by the QUIC connection.
	 */
	isc_tlsctx_t *tlsctx;

	/**
	 * \brief
	 * ALPN value of the TLS handshake.
	 *
	 * \warning
	 * Must be less than 7-bytes, might be increased in the future.
	 */
	isc_constregion_t alpn;

	/**
	 * \brief
	 * Handshake timeout of the state machine
	 *
	 * Must not be `isc_quic_timestamp_invalid`. Zero value disables
	 * timeout.
	 */
	isc_nanosecs_t handshake_timeout;

	/**
	 * \brief
	 * Idle timeout of the state machine
	 *
	 * Must not be `isc_quic_timestamp_invalid`. Zero value disables
	 * timeout.
	 */
	isc_nanosecs_t idle_timeout;
};

void
isc_quic_router_create(isc_mem_t *mctx, size_t cidlen,
		       isc_quic_router_t **routerp);
/**<
 * \brief
 * Create a new QUIC CID router.
 *
 * `cidlen` is the length of the Connection IDs this endpoint issues. It is
 * needed to route incoming Short header (1-RTT) packets, whose Destination
 * Connection ID length is not carried on the wire (RFC9000, Section 5.2).
 *
 * `conn_ref` and `conn_unref` acquire and release a reference on a connection.
 * The router holds a reference for as long as a connection is reachable and
 * takes an extra one on every value it hands out (see isc_quic_router_get_cid()
 * and isc_quic_router_get_stateless_reset()).
 *
 * \par Requires:
 * \li `mctx` is a valid memory context.
 * \li `cidlen` ∈ [1, 20]
 * \li `conn_ref != NULL` and `conn_unref != NULL`
 * \li `routerp != NULL` and `*routerp == NULL`
 */

ISC_REFCOUNT_DECL(isc_quic_router);

isc_result_t
isc_quic_router_add_cid(isc_quic_router_t *router, isc_constregion_t cid,
			isc_tid_t tid, void *conn);
/**<
 * \brief
 * Associate a connection with the given CID.
 *
 * The CID will be copied and thus the parameter free from any lifetime
 * requirements.
 *
 * `tid` is stored alongside the connection and returned by
 * isc_quic_router_get_cid(); it identifies the loop that owns `conn`.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `cid.base != NULL` and `cid.length` ∈ [1, 20]
 * \li `tid >= 0`
 * \li `conn != NULL`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_EXISTS if a connection exists for the given CID
 */

isc_result_t
isc_quic_router_get_cid(isc_quic_router_t *router, isc_constregion_t cid,
			isc_tid_t *tidp, isc_quic_conn_t **connp);
/**<
 * \brief
 * Get the connection associated with a given CID and its thread if `tidp` is
 * not NULL.
 *
 * \note
 * On success `*connp` carries an extra reference on the connection, taken with
 * the router's `conn_ref` callback; the caller must release it with the
 * matching `conn_unref` once done. This keeps the connection alive across the
 * handoff to its owning `tid`, closing the race with a concurrent teardown.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `cid.base != NULL` and `cid.length` ∈ [1, 20]
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTFOUND if no connection exists for the given CID.
 */

isc_result_t
isc_quic_router_del_cid(isc_quic_router_t *router, isc_constregion_t cid);
/**<
 * \brief
 * Remove the connection associated with the given CID.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `cid.base != NULL` and `cid.length` ∈ [1, 20]
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTFOUND if no connection exists for the given CID.
 */

isc_result_t
isc_quic_router_add_stateless_reset(
	isc_quic_router_t *router,
	const uint8_t	   token[restrict ISC_QUIC_STATELESS_TOKEN_LENGTH],
	isc_tid_t tid, void *conn);
/**<
 * \brief
 * Associate a connection with the given stateless reset token.
 *
 * `tid` is stored alongside the connection and returned by
 * isc_quic_router_get_stateless_reset(); it identifies the loop that owns
 * `conn`.
 *
 * The token will be copied and thus the parameter free from any lifetime
 * requirements.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `token != NULL`
 * \li `tid >= 0`
 * \li `conn != NULL`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_EXISTS if a connection is already associated with the given
 * token.
 */

isc_result_t
isc_quic_router_get_stateless_reset(
	isc_quic_router_t *router,
	const uint8_t token[const restrict ISC_QUIC_STATELESS_TOKEN_LENGTH],
	isc_tid_t *tidp, isc_quic_conn_t **connp);
/**<
 * \brief
 * Get the connection associated with the given stateless reset token and its
 * thread if `tidp` is not NULL.
 *
 * \note
 * On success `*connp` carries an extra reference on the connection (see
 * isc_quic_router_get_cid()); the caller must release it with the router's
 * `conn_unref` callback.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `token` != NULL
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTFOUND if no connection exists for the given token.
 */

isc_result_t
isc_quic_router_del_stateless_reset(
	isc_quic_router_t *router,
	const uint8_t token[const restrict ISC_QUIC_STATELESS_TOKEN_LENGTH]);
/**<
 * \brief
 * Remove the connection associated with the given stateless reset token.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `token != NULL`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTFOUND if no connection exists for the given token.
 */

isc_result_t
isc_quic_router_handle_packet(isc_quic_router_t	 *router,
			      isc_constregion_t	  packet,
			      isc_quic_version_t *versionp,
			      isc_constregion_t	 *dcidp,
			      isc_constregion_t *scidp, isc_tid_t *tidp,
			      isc_quic_conn_t **connp);
/**<
 * \brief
 * Extracts the associated value and relevant information of a given QUIC
 * packet.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `packet.base != NULL` and `packet.length != 0`
 * \li `dcidp != NULL`
 * \li `scidp != NULL`
 * \li `connp != NULL` and `*connp == NULL`
 *
 * It checks for the following
 * \li Check if the packet header is valid. If so, extract relevant information.
 * \li If the DCID is associated with a value, return it.
 * \li Otherwise, check if the packet version is unknown. If so, also check if
 * it has a stateless reset token.
 * \li Check if it can be accepted as a handshake.
 *
 * \warning
 * The router will **NOT** automatically remove the CID on stateless reset.
 *
 * \note
 * On return, `*dcidp` and `*scidp` alias into `packet.base`; they are only
 * valid for as long as `packet` is, and are left unset on the
 * ISC_R_INVALIDPROTO path (where the header could not be decoded).
 *
 * \note
 * When a connection is returned via `*connp` (ISC_R_SUCCESS or
 * ISC_R_CONNECTIONRESET), it carries an extra reference the caller must release
 * with the router's `conn_unref` callback (see isc_quic_router_get_cid()).
 *
 * \retval ISC_R_SUCCESS when an associated connection for the packet is found
 * \retval ISC_R_CONNECTIONRESET when a stateless reset packet for a session has
 * been found.
 * \retval ISC_R_NOTFOUND when the packet should be accepted as the handshake of
 * a new connection.
 * \retval ISC_R_NOTIMPLEMENTED when the version is unsupported and a Version
 * Negotiation packet should be sent; `*dcidp` and `*scidp` are populated with
 * the peer's connection IDs (which may exceed ISC_QUIC_CID_MAX_LENGTH).
 * \retval ISC_R_INVALIDPROTO on packet misformat
 * \retval ISC_R_UNEXPECTED when a Short header (1-RTT) packet is not associated
 * with a connection and is not a known stateless reset. The caller MAY respond
 * with a stateless reset (RFC9000, Section 10.3).
 * \retval ISC_R_IGNORE when the packet should be dropped silently: a Long
 * header packet that cannot be accepted as a handshake (e.g. Handshake or
 * 0-RTT for an unknown connection) or a received Version Negotiation packet.
 * Unlike ISC_R_UNEXPECTED, the caller MUST NOT send a stateless reset in
 * response (RFC9000, Section 10.3).
 */

isc_result_t
isc_quic_conn_client_create(isc_mem_t *mctx, isc_quic_router_t *router,
			    const isc_quic_conn_callbacks_t *callbacks,
			    void			    *callback_arg,
			    const isc_quic_conn_options_t   *options,
			    const char *sni, const isc_sockaddr_t *local,
			    const isc_sockaddr_t *peer,
			    isc_quic_conn_t	**connp);

/**<
 * \brief
 * Create a new client state machine.
 *
 * \par Requires
 * \li `mctx` is a valid memory context
 * \li `router` is a valid QUIC router
 * \li `options != NULL` and is valid
 * \li `version` is a valid and defined QUIC version
 * \li `sni` points to a valid SNI string
 * \li `local != NULL`
 * \li `peer != NULL`
 * \li `connp != NULL` and `*connp == NULL`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the given QUIC version is not supported
 * \retval ISC_R_TLSERROR on internal TLS failure
 * \retval ISC_R_NOMEMORY on allocation failure
 * \retval ISC_R_FAILURE on unknown failure
 */

isc_result_t
isc_quic_conn_server_create(
	isc_mem_t *mctx, isc_quic_router_t *router,
	const isc_quic_conn_callbacks_t *callbacks, void *callback_arg,
	const isc_quic_conn_options_t *options, isc_constregion_t initial_dcid,
	isc_constregion_t initial_scid, const isc_sockaddr_t *local,
	const isc_sockaddr_t *peer, isc_quic_conn_t **connp);
/**<
 * \brief
 * Create a new server state machine
 *
 * \par Requires
 * \li `mctx` is a valid memory context
 * \li `router` is a valid QUIC router
 * \li `options != NULL` and is valid
 * \li `initial_version` is a valid and defined QUIC version
 * \li `initial_dcid.base != NULL` and `initial_dcid.length` ∈ [1, 20]
 * \li `initial_scid.base != NULL` and `initial_scid.length` ∈ [1, 20]
 * \li `local != NULL`
 * \li `peer != NULL`
 * \li `connp != NULL` and `*connp == NULL`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the given QUIC version is not supported
 * \retval ISC_R_TLSERROR on internal TLS failure
 * \retval ISC_R_NOMEMORY on allocation failure
 * \retval ISC_R_FAILURE on unknown failure
 */

ISC_REFCOUNT_DECL(isc_quic_conn);

isc_result_t
isc_quic_tlsctx_client_configure(isc_tlsctx_t *tlsctx);
/**<
 * \brief
 * Configure the client TLS context to be used for QUIC connections.
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_TLSERROR on failure
 */

isc_result_t
isc_quic_tlsctx_server_configure(isc_tlsctx_t *tlsctx);
/**<
 * \brief
 * Configure the server TLS context to be used for QUIC connections.
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_TLSERROR on failure
 */

#ifdef HAVE_LIBNGTCP2
void
isc__quic_initialize(void);

void
isc__quic_shutdown(void);
#else /* HAVE_LIBNGTCP2 */
#define isc__quic_initialize()
#define isc__quic_shutdown()
#endif /* HAVE_LIBNGTCP2 */
