<!--
 - Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 -
 - This Source Code Form is subject to the terms of the Mozilla Public
 - License, v. 2.0. If a copy of the MPL was not distributed with this
 - file, you can obtain one at https://mozilla.org/MPL/2.0/.
 -
 - See the COPYRIGHT file distributed with this work for additional
 - information regarding copyright ownership.
-->
## RDATA Types

### Overview

The dns rdata routines (`dns_rdata_fromtext()`,
`dns_rdata_totext()`, `dns_rdata_fromwire()`,
`dns_rdata_towire()` `dns_rdata_fromstruct()`,
`dns_rdata_tostruct()` and `dns_rdata_compare()`)
are designed to provide a single set of routines
for encoding, decoding and comparing dns data preventing the problems that
occurred in BIND 8.x and earlier, in which there were multiple places in the
code base that decoded wire format to internal format or compared rdata,
sometimes with subtly different behaviour (bugs), and sometimes failing to
support a particular type, leading to internal inconsistency.

Each of these generic routines calls type-specific routines that provide
the type-specific details.

From time to time new types are defined and it is necessary to add these types
into the existing structure.  This document is written to provide instruction
on how to do this.

### Adding new RDATA types

Adding a new rdata type requires determining whether the new rdata type is
class-specific or generic, writing code to perform the rdata operations for the
type, then integrating it into the build by placing the code into the rdata
hierarchy at the correct location under `lib/dns/rdata`.  Running `make clean`
followed by `make` in `lib/dns` will cause the new rdata type to be picked up
and compiled.

Each rdata module must perform the following operations:

* Convert from text format to internal format
* Convert from internal format to text format
* Convert from wire format to internal format
* Convert from internal format to wire format
* Convert from a structure to internal format
* Convert from internal format to a structure
* Compare two rdata in internal format

There is an additional set of support functions and macros only available to
rdata code.

#### RDATA Hierarchy

The `rdata` hierarchy has the following format.

        rdata/
                generic/
                        typename_typenumber.h
                classname_classnumber/
                        typename_typenumber.h

Initial rdata hierarchy:

        rdata/
                generic/
                        ns_2.h
                        md_3.h
                        mf_4.h
                        cname_5.h
                        soa_6.h
                        mb_7.h
                        mg_8.h
                        mr_9.h
                        null_10.h
                        ptr_12.h
                        hinfo_13.h
                        minfo_14.h
                        mx_15.h
                        txt_16.h
                        rp_17.h
                        afsdb_18.h
                        x25_19.h
                        isdn_20.h
                        rt_21.h
                        sig_24.h
                        key_25.h
                        gpos_27.h
                        loc_29.h
                        nxt_30.h
                        cert_37.h
                        dname_39.h
                        unspec_103.h
                        tkey_249.h
                in_1/
                        a_1.h
                        wks_11.h
                        nsap_22.h
                        nsap-ptr_23.h
                        px_26.h
                        aaaa_28.h
                        srv_33.h
                        naptr_35.h
                        kx_36.h
                        a6_38.h
                any_255/
                        tsig_250.h

#### CLASSNAME and TYPENAME

Class and type names must be from the following alphabet and less that 11
characters in length or otherwise they will be ignored.
Permissible alphabet: a to z, 0 to 9 and dash (-).
Dash is mapped to underscore (_) for the C function names below.

#### Internal Format

The internal format chosen is DNS wire format without any compression being
applied to domain names in the rdata.

#### Converting from text format to internal format

The functions to convert from text format has the following call formats and
is declared as follows for class-generic functions.

        static dns_result_t
        fromtext_typename(dns_rdataclass_t class, dns_rdatatype_t type,
                          isc_lex_t *lexer, dns_name_t *origin,
                          bool downcase, isc_buffer_t *target);

Class specific functions contain the class name in addition to the
type name.

        static dns_result_t
        fromtext_classname_typename(dns_rdataclass_t class,
                                    dns_rdatatype_t type,
                                    isc_lex_t *lexer,
                                    dns_name_t *origin,
                                    bool downcase,
                                    isc_buffer_t *target);

|Parameter|Description |
|---------|-----------------------|
|`class`|This argument should be ignored when used with a class-generic RR type, otherwise `REQUIRE(class == <value>)` should be present at the start of the function.|
|`type`|This should be tested with a `REQUIRE(type == <value>)` statement at the beginning of the function.|
|`lexer`|This is used to read the input text stream.|
|`origin`|This is a absolute name used to qualify unqualified / partially qualified domain names in the text stream.  It is passed to the name parsing routines.|
|`downcase`|This is passed to the name parsing routines to determine whether to downcase the names it generates or leave them in the case they are presented in.|
|`target`|This is a `BINARY` buffer into which to write the internal format of the rdata record being read.|

`fromtext_typename()` reads tokens from `lexer`,
up to but not including the end of line (EOL) token or end of file (EOF) token.
If the EOL / EOF token is read it should be returned to the input stream.

`gettoken()` should be used to read the next token from the input stream.

`isc_lex_ungettoken()` should be used to return EOL / EOF (or any other token)
to the input stream if the EOL / EOF token is read.

Unused tokens will cause `dns_rdata_fromtext()` to return `DNS_R_EXTRATOKEN` if
`fromtext_typename()` was successful.

`fromtext_typename()` reads external input and as such is a high
security area and must be paranoid about its input.

#### Converting from internal format to text format

        static dns_result_t
        totext_typename(dns_rdata_t *rdata, dns_name_t *origin,
                        isc_buffer_t *target);

        static dns_result_t
        totext_classname_typename(dns_rdata_t *rdata,
                        dns_name_t *origin, isc_buffer_t *target);

|Parameter|Description |
|---------|-----------------------|
|`rdata`|This is the rdata record to be converted from internal format to text.  `rdata->type` (and `rdata->class` for class-specific RR types) should be checked at the start of the function with `REQUIRE` statements.|
|`origin`|If this is not `NULL`, then any domain names with this suffix should be written out as unqualified subdomains.  `name_prefix()` can be used to check whether `origin` is `NULL` and provide the correct arguments to the name conversion routines.|
|`target`|This is a `TEXT` buffer into which to write the output.|

#### Converting from wire format to internal format

        static dns_result_t
        fromwire_typename(dns_rdataclass_t class,
                           dns_rdatatype_t type,
                           isc_buffer_t *source,
                           dns_decompress_t *dctx,
                           bool downcase,
                           isc_buffer_t *target);

        static dns_result_t
        fromwire_classname_typename(dns_rdataclass_t class,
                                    dns_rdatatype_t type,
                                    isc_buffer_t *source,
                                    dns_decompress_t *dctx,
                                    bool downcase,
                                    isc_buffer_t *target);

`fromwire_classname_typename()` is required to set the valid
decompression methods if there is a domain name in the rdata.

        if (dns_decompress_edns(dctx) >= # || !dns_decompress_strict(dctx))
                dns_decompress_setmethods(dctx, DNS_COMPRESS_ALL);
        else
                dns_decompress_setmethods(dctx, DNS_COMPRESS_GLOBAL14);

|Parameter|Description |
|---------|-----------------------|
|`class`|This argument should be ignored when used with a class-generic RR type otherwise `REQUIRE(class == <value>)` should be present at the start of the function.|
|`type`|This should be tested with a `REQUIRE(type == <value>)` statement at the beginning of the function.|
|`source`|This is a `BINARY` buffer with the `active` region containing a resource record in wire format.|
|`dctx`|This is the decompression context and is passed to `dns_name_fromwire()`, along with `downcase`, to enable a compressed domain name to be extracted from the source.|
|`downcase`|This is passed to `dns_name_fromwire()` to say whether the extracted domain name should be downcased during the extraction.|
|`target`|This is a `BINARY` buffer into which the decompressed and checked resource record is written.|

`fromwire_typename()` is a security sensitive routine
as it reads external data, and should take extreme care to ensure that
the input data matches its description.

If the `active` buffer is not empty at completion and
`fromwire_typename()` was otherwise successful, `dns_rdata_fromwire()`
will return `DNS_R_EXTRADATA`.

#### Converting from internal format to wire format

        static dns_result_t
        towire_typename(dns_rdata_t *rdata,
                        dns_compress_t *cctx,
                        isc_buffer_t *target);

        static dns_result_t
        towire_classname_typename(dns_rdata_t *rdata,
                                  dns_compress_t *cctx,
                                  isc_buffer_t *target);

`towire_classname_typename()` is required to set the
allowed name compression methods based on the EDNS version, if there
is a domain name in the rdata.

        if (dns_compress_getedns(cctx) >= #)
                dns_compress_setmethods(cctx, DNS_COMPRESS_ALL);
        else
                dns_compress_setmethods(cctx, DNS_COMPRESS_GLOBAL14);

|Parameter|Description |
|---------|-----------------------|
|`rdata`|This is the rdata record to be converted from internal format to text.  `rdata->type` (and `rdata->class` for class-specific RR types) should be checked at the start of the function with `REQUIRE` statements.|
|`cctx`|This is the compression context. It should be passed to `dns_name_towire()` when putting domain names on the wire.|
|`target`|This is a `BINARY` buffer into which to write the rdata|

Simple RR types without domain names can use the following code to
transfer the contents of the `rdata` to the target buffer.

        return (mem_tobuffer(target, rdata->data, rdata->length));

#### Converting from a structure to internal format

        static dns_result_t
        fromstruct_typename(dns_rdataclass_t class,
                            dns_rdatatype_t type,
                            void *source,
                            isc_buffer_t *target);

        static dns_result_t
        fromstruct_classname_typename(dns_rdataclass_t class,
                                      dns_rdatatype_t type,
                                      void *source,
                                      isc_buffer_t *target);

|Parameter|Description |
|---------|-----------------------|
|`class`|This argument should be ignored when used with a class-generic RR type otherwise `REQUIRE(class == <value>)` should be present at the start of the function.|
|`type`|This should be tested with a `REQUIRE(type == <value>)` statement at the beginning of the function.|
|`source`|This points to a type-specific structure.|
|`target`|This is a `BINARY` buffer into which to write the internal format of the rdata record being read in.|

#### Converting from internal format to a structure

        static dns_result_t
        tostruct_typename(dns_rdata_t *rdata, void *target);

        static dns_result_t
        tostruct_classname_typename(dns_rdata_t *rdata, void *target);

|Parameter|Description |
|---------|-----------------------|
|`rdata`|This is the rdata record to be converted from internal format to a structure. `rdata->type` (and `rdata->class` for class-specific RR types) should be checked at the start of the function with `REQUIRE` statements.|
|`target`|Pointer to a type-specific structure.|

#### Comparing two rdata in internal format

        static int
        compare_typename(dns_rdata_t *rdata1,
                         dns_rdata_t *rdata2);

        static int
        compare_classname_typename(dns_rdata_t *rdata1,
                                   dns_rdata_t *rdata2);

This function compares `rdata1` and `rdata2` as required for DNSSEC
ordering.  The routine should ensure that the `type` and `class` of the
two rdata match with `REQUIRE(rdata1->type == rdata2->type);` and
`REQUIRE(rdata1->class == rdata2->class);` statements. The
`rdata->type` should also be verified, and if the RR type is
class-specific, also the `rdata->class`.

`compare_classname_typename()` returns -1, 0, 1.

#### Support Functions

The following static support functions are available to use.

        static unsigned int
        name_length(dns_name_t *name);

Returns the length of `name`.

        static dns_result_t
        txt_totext(isc_region_t *source, isc_buffer_t *target);

Extracts the octet-length-tagged text string at the start of
`source` and writes it as a quoted string to `target`.
`source` is adjusted so that it points to first octet after the
text string.

Returns `DNS_R_NOSPACE` or `DNS_R_SUCCESS`.

        static dns_result_t
        txt_fromtext(isc_textregion_t *source, isc_buffer_t *target);

Take the text region `source` and convert it to a length-tagged
text string, writing it to `target`.

Returns `DNS_R_NOSPACE`, `DNS_R_TEXTTOLONG` or `DNS_R_SUCCESS`.

        static dns_result_t
        txt_fromwire(isc_buffer_t *source, isc_buffer_t *target);

Read an octet-length-tagged text string from `source` and write it to `target`.
Ensures that octet-length-tagged text string was wholly within the active area
of `source`.  Adjusts the active area of `source` so that it refers to the
first octet after the octet-length-tagged text string.

Returns `DNS_R_UNEXPECTEDEND`, `DNS_R_NOSPACE` or `DNS_R_SUCCESS`.

        static bool
        name_prefix(dns_name_t *name, dns_name_t *origin, dns_name_t *target);

If `origin` is NULL or the root label, set `target` to refer to `name` and
return `false`.  Otherwise, see if `name` is a subdomain of `origin` and
not equal to it.  If so, make `target` refer to the prefix of `name` and return
`true`.  Otherwise, make `target` refer to `name` and return `false`.

Typical use:

        static dns_result_t
        totext_typename(dns_rdata_t *rdata, dns_name_t *origin,
                        isc_buffer_t * target)
        {
                isc_region_t region;
                dns_name_t name, prefix;
                bool sub;

                dns_name_init(&name, NULL);
                dns_name_init(&prefix, NULL);
                dns_rdata_toregion(rdata, &region);
                dns_name_fromregion(&name, &region);
                sub = name_prefix(&name, origin, &prefix);
                return (dns_name_totext(&prefix, sub, target));
        }

static dns_result_t
str_totext(char *source, isc_buffer_t *target);

Adds the `NULL`-terminated string `source`, up to but not including `NULL`,
to `target`.

Returns `DNS_R_NOSPACE` and `DNS_R_SUCCESS`.

        static bool
        buffer_empty(isc_buffer_t *source);

Returns `true` if the active region of `source` is
empty otherwise `false`.

        static void
        buffer_fromregion(isc_buffer_t *buffer, isc_region_t *region,
                          unsigned int type);

Make `buffer` refer to the memory in `region` and make it active.

        static dns_result_t
        uint32_tobuffer(uint32_t value, isc_buffer_t *target);

Write the 32 bit `value` in network order to `target`.

Returns `DNS_R_NOSPACE` and `DNS_R_SUCCESS`.

static dns_result_t
uint16_tobuffer(uint32_t value, isc_buffer_t *target);

Write them 16 bit `value` in network order to `target`.

Returns `ISC_R_RANGE`, `DNS_R_NOSPACE` and `DNS_R_SUCCESS`.

        static uint32_t
        uint32_fromregion(isc_region_t *region);

Returns the 32 bit at the start of `region` in host byte order.

Requires `(region->length >= 4)`.

        static uint16_t
        uint16_fromregion(isc_region_t *region);

Returns the 16 bit at the start of `region` in host byte order.

Requires `(region->length >= 2)`.

        static dns_result_t
        gettoken(isc_lex_t *lexer, isc_token_t *token,
                 isc_tokentype_t expect, bool eol);

Gets the next token from the input stream `lexer`. Ensures that the returned
token matches `expect` (isc_tokentype_qstring can also return
isc_tokentype_string), or isc_tokentype_eol and isc_tokentype_eof if `eol` is
`true`.

Returns `DNS_R_UNEXPECTED`, `DNS_R_UNEXPECTEDEND`, `DNS_R_UNEXPECTEDTOKEN` and
`DNS_R_SUCCESS`.

        static dns_result_t
        mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length);

Add the memory referred to by `base` to `target`.

Returns `DNS_R_NOSPACE` and `DNS_R_SUCCESS`.

        static int
        compare_region(isc_region_t *r1, isc_region_t *r2)

Compares two regions, returning -1, 0, 1 based on their DNSSEC ordering.

        static int
        hexvalue(char value);

Returns the hexadecimal value of `value`, or -1 if not a hexadecimal character.

        static int
        decvalue(char value);

Returns the decimal value of `value`, or -1 if not a decimal character.

        static dns_result_t
        base64_totext(isc_region_t *source, isc_buffer_t *target);

Convert the region referred to by `source` to Base64 encoded text and put it
into `target`.

Returns `DNS_R_NOSPACE` or `DNS_R_SUCCESS`.

        static dns_result_t
        base64_tobuffer(isc_lex_t *lexer, isc_buffer_t *target, int length);

Read a series of tokens from `lexer` that containing base64 data until one of
end of line, `length` (`length` >= 0) bytes have been read or base64 pad
characters are seen.  If `length` < 0 it is ignored; otherwise, it is an
error if there are not `length` octets of data or if when processing a
token, `length` octets would have been exceeded.

Returns `DNS_R_BADBASE64`, `DNS_R_UNEXPECTED`, `DNS_R_UNEXPECTEDEND`,
`DNS_R_UNEXPECTEDTOKEN` and `DNS_R_SUCCESS`.

        static dns_result_t
        time_totext(unsigned long value, isc_buffer_t *target);`

Convert the date represented by `value` into YYYYMMDDHHMMSS format
taking into account the active epochs. This code is Y2K and Y2038 compliant.

Returns `DNS_R_NOSPACE` and `DNS_R_SUCCESS`.

        static dns_result_t
        time_tobuffer(char *source, isc_buffer_t *target);

Take the date in `source` and convert it to seconds since January 1, 1970
(ignoring leap seconds) and place the least significant 32 bits into `target`.

Returns `ISC_R_RANGE`, `DNS_R_SYNTAX`, `DNS_R_NOSPACE` and `DNS_R_SUCCESS`.

#### Support Macros

The following macro is available:

`RETERR(x)`

Evaluate `x` and call `return (<value of x>);` if the result is
not `ISC_R_SUCCESS`.
