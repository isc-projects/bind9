/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 * SPDX-License-Identifier: MPL-2.0
 */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

#include <isc/util.h>

#include "accumulator.pb-c.h"

int
main(void) {
	uint64_t value = 0;
	uint32_t wire_length;
	unsigned char data[64];

	while (true) {
		size_t n = fread(&wire_length, 1, sizeof(wire_length), stdin);
		if (n == 0 && feof(stdin)) {
			break;
		}
		RUNTIME_CHECK(n == sizeof(wire_length));
		size_t length = ntohl(wire_length);
		RUNTIME_CHECK(length > 0 && length <= sizeof(data));
		RUNTIME_CHECK(fread(data, 1, length, stdin) == length);
		Accumulator__Request *request =
			accumulator__request__unpack(NULL, length, data);
		RUNTIME_CHECK(request != NULL);
		switch (request->command_case) {
		case ACCUMULATOR__REQUEST__COMMAND_RESET:
			value = request->reset;
			break;
		case ACCUMULATOR__REQUEST__COMMAND_ADD:
			value += request->add;
			break;
		case ACCUMULATOR__REQUEST__COMMAND_SUBTRACT:
			value -= request->subtract;
			break;
		default:
			UNREACHABLE();
		}
		accumulator__request__free_unpacked(request, NULL);

		Accumulator__Response response = {
			.base = PROTOBUF_C_MESSAGE_INIT(
				&accumulator__response__descriptor),
			.value = value,
		};
		length = accumulator__response__get_packed_size(&response);
		RUNTIME_CHECK(length <= sizeof(data));
		accumulator__response__pack(&response, data);
		wire_length = htonl(length);
		RUNTIME_CHECK(fwrite(&wire_length, 1, sizeof(wire_length),
				     stdout) == sizeof(wire_length));
		RUNTIME_CHECK(fwrite(data, 1, length, stdout) == length);
		RUNTIME_CHECK(fflush(stdout) == 0);
	}
	return 0;
}
