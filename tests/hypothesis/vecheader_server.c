/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 * SPDX-License-Identifier: MPL-2.0
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/rdatavec.h>

#include "rdatavec_p.h"
#include "vecheader.pb-c.h"

static void
set_owner_case(dns_vecheader_t *header, const ProtobufCBinaryData *owner) {
	dns_name_t name = DNS_NAME_INITEMPTY;
	isc_region_t region = {
		.base = owner->data,
		.length = owner->len,
	};
	dns_name_fromregion(&name, &region);
	dns_vecheader_setownercase(header, &name);
}

/* All input bytes are logical RDATA, never a serialized C header. */
static isc_result_t
make_header(isc_mem_t *mctx, const Vec__Header *input, dns_rdatatype_t type,
	    uint32_t limit, dns_vecheader_t **output) {
	dns_rdatalist_t list = {
		.rdata = ISC_LIST_INITIALIZER,
		.link = ISC_LINK_INITIALIZER,
		.type = type,
		.covers = type == dns_rdatatype_rrsig ? dns_rdatatype_a : 0,
		.rdclass = dns_rdataclass_in,
		.ttl = input->ttl,
	};
	dns_rdataset_t set = DNS_RDATASET_INIT;
	dns_rdata_t *records = calloc(input->n_records + 1, sizeof(*records));
	isc_region_t region;
	isc_result_t result = ISC_R_SUCCESS;
	RUNTIME_CHECK(records != NULL);
	RUNTIME_CHECK(input->n_offline == input->n_records);
	memset(list.upper, 0xeb, sizeof(list.upper));
	list.upper[0] &= ~0x01;
	for (size_t i = 0; i < input->n_records; i++) {
		/* protobuf-c uses NULL for empty bytes; comparators need a
		 * base. */
		static unsigned char empty;
		region = (isc_region_t){
			.base = input->records[i].len == 0
					? &empty
					: input->records[i].data,
			.length = input->records[i].len,
		};
		dns_rdata_init(&records[i]);
		dns_rdata_fromregion(&records[i], list.rdclass, type, &region);
		if (input->offline[i]) {
			records[i].flags |= DNS_RDATA_OFFLINE;
		}
		ISC_LIST_APPEND(list.rdata, &records[i], link);
	}
	dns_rdatalist_tordataset(&list, &set);
	set.trust = input->trust;
	if (input->n_records == 0) {
		/* Empty headers represent tombstones, not empty rdatasets. */
		*output = dns_vecheader_new(mctx);
		(*output)->typepair = DNS_TYPEPAIR_VALUE(type, list.covers);
		(*output)->ttl = input->ttl;
		atomic_store(&(*output)->trust, input->trust);
	} else {
		result = dns_rdatavec_fromrdataset(&set, mctx, &region, limit);
		if (result == ISC_R_SUCCESS) {
			*output = (dns_vecheader_t *)region.base;
		}
	}
	dns_rdataset_disassociate(&set);
	free(records);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	(*output)->serial = input->serial;
	(*output)->resign = input->resign_time;
	if (input->resign) {
		DNS_VECHEADER_SETATTR(*output, DNS_VECHEADERATTR_RESIGN);
	}
	if (input->has_owner) {
		set_owner_case(*output, &input->owner);
	}
	return result;
}

static void
write_response(Vec__Response *response) {
	size_t length = vec__response__get_packed_size(response);
	unsigned char *data = malloc(length);
	uint32_t wire_length = htonl(length);
	RUNTIME_CHECK(data != NULL);
	vec__response__pack(response, data);
	RUNTIME_CHECK(fwrite(&wire_length, 1, 4, stdout) == 4);
	RUNTIME_CHECK(fwrite(data, 1, length, stdout) == length);
	RUNTIME_CHECK(fflush(stdout) == 0);
	free(data);
}

static Vec__Result
result_to_proto(isc_result_t result) {
	switch (result) {
	case ISC_R_SUCCESS:
		return VEC__RESULT__SUCCESS;
	case DNS_R_TOOMANYRECORDS:
		return VEC__RESULT__TOO_MANY_RECORDS;
	case DNS_R_NOTEXACT:
		return VEC__RESULT__NOT_EXACT;
	case DNS_R_UNCHANGED:
		return VEC__RESULT__UNCHANGED;
	case DNS_R_SINGLETON:
		return VEC__RESULT__SINGLETON;
	case DNS_R_NXRRSET:
		return VEC__RESULT__NXRRSET;
	case ISC_R_NOSPACE:
		return VEC__RESULT__NO_SPACE;
	case ISC_R_FAILURE:
		return VEC__RESULT__FAILURE;
	default:
		fprintf(stderr, "unexpected vecheader result: %s\n",
			isc_result_toid(result));
		abort();
	}
}

static void
reply(isc_result_t result, dns_vecheader_t *header, const Vec__Header *owner) {
	Vec__Response response = {
		.base = PROTOBUF_C_MESSAGE_INIT(&vec__response__descriptor),
		.result = result_to_proto(result),
	};
	unsigned char namebytes[255];
	if (header == NULL) {
		write_response(&response);
		return;
	}
	Vec__Header value = {
		.base = PROTOBUF_C_MESSAGE_INIT(&vec__header__descriptor),
		.has_ttl = true,
		.ttl = header->ttl,
		.has_trust = true,
		.trust = atomic_load(&header->trust),
		.has_serial = true,
		.serial = header->serial,
		.has_resign = true,
		.resign = RESIGN(header),
		.has_resign_time = true,
		.resign_time = header->resign,
		.records = calloc(header->count + 1, sizeof(*value.records)),
		.offline = calloc(header->count + 1, sizeof(*value.offline)),
	};
	response = (Vec__Response){
		.base = PROTOBUF_C_MESSAGE_INIT(&vec__response__descriptor),
		.result = result_to_proto(result),
		.header = &value,
		.has_count = true,
		.count = dns_rdatavec_count(header),
		.has_raw_length = true,
		.raw_length = header->raw_length,
		.has_size = true,
		.size = dns_rdatavec_size(header),
		.has_header_size = true,
		.header_size = sizeof(*header),
		.has_type = true,
		.type = DNS_TYPEPAIR_TYPE(header->typepair),
		.has_covers = true,
		.covers = DNS_TYPEPAIR_COVERS(header->typepair),
		.has_case_set = true,
		.case_set = CASESET(header),
		.has_case_lower = true,
		.case_lower = CASEFULLYLOWER(header),
		.has_bitmap = true,
		.bitmap = {
			.len = sizeof(header->upper),
			.data = header->upper,
		},
	};
	RUNTIME_CHECK(value.records != NULL && value.offline != NULL);
	rdatavec_iter_t iter;
	DNS_VECHEADER_FOREACH(&iter, header, dns_rdataclass_in) {
		dns_rdata_t data = DNS_RDATA_INIT;
		vecheader_current(&iter, &data);
		dns_rdata_t again = DNS_RDATA_INIT;
		vecheader_current(&iter, &again);
		RUNTIME_CHECK(data.data == again.data &&
			      data.length == again.length &&
			      data.flags == again.flags);
		RUNTIME_CHECK(value.n_records < header->count);
		value.records[value.n_records++] = (ProtobufCBinaryData){
			.len = data.length,
			.data = data.data,
		};
		value.offline[value.n_offline++] = (data.flags &
						    DNS_RDATA_OFFLINE) != 0;
	}
	RUNTIME_CHECK(value.n_records == header->count);
	RUNTIME_CHECK(vecheader_next(&iter) == ISC_R_NOMORE);
	RUNTIME_CHECK(vecheader_next(&iter) == ISC_R_NOMORE);
	if (owner->has_owner) {
		RUNTIME_CHECK(owner->owner.len <= sizeof(namebytes));
		memmove(namebytes, owner->owner.data, owner->owner.len);
		isc_region_t region = {
			.base = namebytes,
			.length = owner->owner.len,
		};
		dns_name_t name = DNS_NAME_INITEMPTY;
		dns_name_fromregion(&name, &region);
		RUNTIME_CHECK(dns_name_downcase(&name, &name) == ISC_R_SUCCESS);
		dns_rdataset_t set = {
			.magic = DNS_RDATASET_MAGIC,
			.link = ISC_LINK_INITIALIZER,
			.methods = &dns_rdatavec_rdatasetmethods,
			.vec.header = dns_vecheader_ref(header),
		};
		dns_rdataset_getownercase(&set, &name);
		dns_rdataset_disassociate(&set);
		response.has_applied_owner = true;
		response.applied_owner = (ProtobufCBinaryData){
			.len = name.length,
			.data = name.ndata,
		};
	}
	write_response(&response);
	free(value.records);
	free(value.offline);
}

static void
execute(const Vec__Request *request) {
	isc_mem_t *mctx = NULL;
	dns_vecheader_t *left = NULL, *right = NULL, *output = NULL;
	const Vec__Header *owner = NULL;
	Vec__Header owner_input;
	isc_result_t result = ISC_R_FAILURE;
	isc_mem_create("vecheader-test", &mctx);
	switch (request->command_case) {
	case VEC__REQUEST__COMMAND_CONSTRUCT: {
		const Vec__Construct *command = request->construct;
		owner = command->header;
		result = make_header(mctx, command->header, command->type,
				     command->limit, &output);
		break;
	}
	case VEC__REQUEST__COMMAND_COPY: {
		const Vec__Copy *command = request->copy;
		owner = command->header;
		result = make_header(mctx, command->header, command->type, 0,
				     &left);
		if (result != ISC_R_SUCCESS) {
			break;
		}
		dns_rdataset_t set = {
			.magic = DNS_RDATASET_MAGIC,
			.link = ISC_LINK_INITIALIZER,
			.methods = &dns_rdatavec_rdatasetmethods,
			.vec.header = dns_vecheader_ref(left),
			.type = command->type,
			.covers = DNS_TYPEPAIR_COVERS(left->typepair),
			.rdclass = dns_rdataclass_in,
			.ttl = left->ttl,
			.trust = atomic_load(&left->trust),
		};
		isc_region_t region;
		result = dns_rdatavec_fromrdataset(&set, mctx, &region, 0);
		if (result == ISC_R_SUCCESS) {
			output = (dns_vecheader_t *)region.base;
		}
		dns_rdataset_disassociate(&set);
		break;
	}
	case VEC__REQUEST__COMMAND_MERGE: {
		const Vec__Merge *command = request->merge;
		owner = command->left;
		result = make_header(mctx, command->left, command->type, 0,
				     &left);
		if (result != ISC_R_SUCCESS) {
			break;
		}
		result = make_header(mctx, command->right, command->type, 0,
				     &right);
		if (result != ISC_R_SUCCESS) {
			break;
		}
		result = dns_rdatavec_merge(
			left, right, mctx, dns_rdataclass_in, command->type,
			command->flags, command->limit, &output);
		break;
	}
	case VEC__REQUEST__COMMAND_SUBTRACT: {
		const Vec__Subtract *command = request->subtract;
		owner = command->left;
		result = make_header(mctx, command->left, command->type, 0,
				     &left);
		if (result != ISC_R_SUCCESS) {
			break;
		}
		result = make_header(mctx, command->right, command->type, 0,
				     &right);
		if (result != ISC_R_SUCCESS) {
			break;
		}
		result = dns_rdatavec_subtract(left, right, mctx,
					       dns_rdataclass_in, command->type,
					       command->flags, &output);
		break;
	}
	case VEC__REQUEST__COMMAND_SET_OWNER_CASE: {
		const Vec__SetOwnerCase *command = request->set_owner_case;
		RUNTIME_CHECK(!command->header->has_owner);
		owner_input = *command->header;
		result = make_header(mctx, &owner_input, command->type, 0,
				     &output);
		owner_input.has_owner = true;
		owner_input.owner = command->owner;
		owner = &owner_input;
		if (result == ISC_R_SUCCESS) {
			set_owner_case(output, &command->owner);
		}
		break;
	}
	default:
		break;
	}
	reply(result, output, owner);
	if (output != NULL) {
		dns_vecheader_unref(output);
	}
	if (right != NULL) {
		dns_vecheader_unref(right);
	}
	if (left != NULL) {
		dns_vecheader_unref(left);
	}
	RUNTIME_CHECK(isc_mem_inuse(mctx) == 0);
	RUNTIME_CHECK(isc_mem_references(mctx) == 1);
	isc_mem_detach(&mctx);
}

int
main(void) {
	uint32_t wire_length;
	while (true) {
		size_t n = fread(&wire_length, 1, 4, stdin);
		if (n == 0 && feof(stdin)) {
			break;
		}
		RUNTIME_CHECK(n == 4);
		size_t length = ntohl(wire_length);
		RUNTIME_CHECK(length > 0 && length <= 4 * 1024 * 1024);
		unsigned char *data = malloc(length);
		RUNTIME_CHECK(data != NULL);
		RUNTIME_CHECK(fread(data, 1, length, stdin) == length);
		Vec__Request *request = vec__request__unpack(NULL, length,
							     data);
		RUNTIME_CHECK(request != NULL);
		execute(request);
		vec__request__free_unpacked(request, NULL);
		free(data);
	}
	return 0;
}
