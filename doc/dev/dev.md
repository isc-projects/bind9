<!--
 - Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 -
 - This Source Code Form is subject to the terms of the Mozilla Public
 - License, v. 2.0. If a copy of the MPL was not distributed with this
 - file, You can obtain one at http://mozilla.org/MPL/2.0/.
 -
 - See the COPYRIGHT file distributed with this work for additional
 - information regarding copyright ownership.
-->
## BIND Developer Information

### Contents

1. [The code review process](#reviews)
1. [Testing](#testing)
    * [System tests](#systest)
    * [Unit tests](#unittest)
1. [BIND system architecture](#arch)
    * [Source tree layout](#layout)
    * [Design by contract](#dbc)
    * [Magic numbers](#magic)
    * [Result codes](#results)
    * [Memory management](#mem)
    * [Lists](#lists)
    * [Buffers and regions](#buffers)
    * [Names](#names)
    * [Rdata Classes](#rdata)
    * [Iterators](#iterators)
    * [Logging](#logging)
    * [Adding a new RR type](#rrtype)
    * [Task and timer model](#tasks)

### <a name="reviews"></a>The code review process

Every line of code comitted to BIND has been reviewed by ISC engineers
first.

The code review process is a dialog between the original author and the
reviewer.  Code inspection, including documentation and tests, is part of
this.  Compiling and running the resulting code should be done in most
cases, even for trivial changes, to ensure that it works as intended. In
particular, a full regression test (`make` `check`) must be run for every
modification so that unexpected side-effects are identified.

When a problem or concern is found by the reviewer, these comments are
placed on the RT ticket so the author can respond.

#### What is reviewed:

First, consideration is given to whether contributed code would
be useful to a significant user base (we can't take on the additional
maintenance and support burden for changes that would only be useful
to a tiny niche).  Second, whether the approach taken is consistent
with ISC's open-internet goals, BIND architecture, and DNS best
practices.  Third, the contribution is checked for correctness and
completness.

Obvious bottlenecks and places where performance or reliability may suffer
are noted as part of the review.

New functions must be adequately commented. Public API functions are
documented in the corresponding header file, static functions in the C
file, above the function header.  Particularly complex code should be
commented throughout the function body as well.

A patch is much more likely to be accepted quickly if it includes
tests providing good coverage of the new code.  Tests for bugfix code
should fail when run against the unmodified code; tests for new feature
code should have good code coverage and address corner cases and error
cases.  Newly added API functions should have unit tests if possible.
(See [testing](#testing).)

Documentation is also reviewed. This includes all user-facing text,
including log messages, manual pages, user manuals and sometimes even
comments; they must be clearly written and consistent with existing style.

#### Steps in code review:

* Read the diff
* Read accompanying notes in the ticket
* Apply the diff to the appropriate branch
* Run `configure` (using at least `--enable-developer --with-atf`)
* Build
* Read the documentation, if any
* Read the tests
* Run the tests
  <br>(In some cases it may be appropriate to run tests against code
  from before the change to ensure that they fail as expected.)

#### Things we look for

* General correctness of approach
* Style errors
* Simple coding errors
* Files inadvertently omitted
* Unnecessarily complex code
* Complex code with insufficient comments
* Lack of boundary checking
* Memory and resource leaks (deallocations must match allocations)
* Places that need `REQUIRE` or `INSIST`
* Thread safety
* Bad function names/variable names
* Overly long functions
* Copies of code that could be unified in a helper function
* Premature optimizations
* Compiler warnings introduced
* Portability issues:
 * Use of non-POSIX library calls or options
 * API changes correctly reflected in Windows `*.def` files
* DNS/protocol problems
* Cut/pasted code that may have been modified in one place but needs to be modified in other places as well
* No tests or inadequate tests
* Testability problems
* No documentation or inadequate documentation
* Grammar, spelling and clarity problems in documentation
* Usability problems

When a patch is contributed which is a good idea but doesn't meet our code
quality requirements, we will often keep the ticket open so that we can
address the issue ourselves later.

Sometimes contributed code is fine, but ISC staff still have to add
documentation and/or tests -- that's okay, but it may take a long time to
get to the top of our priority list.  Ensuring that your patch includes
tests and documentation will reduce delay.

### <a name="testing"></a> Testing

#### <a name="systest"></a> Running system tests

To enable system tests to work, we first need to create the test loopback
interfaces (as root):

        $ cd bin/tests/system
        $ sudo sh ifconfig.sh up
        $ cd ../../..

To run the tests, build BIND (be sure to use --with-atf to run unit
tests), then run `make` `check`.  An easy way to check the results:

        $ make check 2>&1 | tee /tmp/check.out
        $ grep '^R:' /tmp/check.out | sort | uniq -c

This will show all of the test results. One or two "R:SKIPPED" is okay; if
there are a lot of them, then you probably forgot to create the loopback
interfaces in the previous step. (NOTE: the summary of tests that appears at
the end of `make` `check` only summarizes the system test results, not the
unit tests, so you can't rely on it to catch everything.)

To run only the system tests, omitting unit tests:

        $ cd bin/tests/system
        $ sh runall.sh

Or, to run an individual system test:

        $ cd bin/tests/system
        $ sh run.sh <testname>

System tests are in separate directories under `bin/tests/system`.
For example, the "dnssec" test is in `bin/tests/system/dnssec`.

#### Writing system tests

The following standard files are found in system test directories:

- `prereq.sh`: run at the beginning to determine whether the test can be run at all; if not, we see R:SKIPPED

- `setup.sh`: sets up the preconditions for the tests

- `tests.sh`: runs all the test cases. A non-zero return value results in R:FAIL

- `clean.sh`: run at the end to clean up temporary files, but only if the
  test was completed successfully; otherwise the temporary files are left
  in place for inspection.

- `ns[X]`: these subdirectories contain test name servers that can be
  queried or can interact with each other. (For example, `ns1` might be
  running as a root server, `ns2` as a TLD server, and `ns3` as a recursive
  resolver.)  The value of X indicates the address the server listens on:
  for example, `ns2` listens on 10.53.0.2, and ns4 on 10.53.0.4. All test
  servers use port 5300 so they don't need to run as root. All servers
  log at the highest debug level, and the logs are captured in the file
  `nsX/named.run`.

- `ans[X]`: like `ns[X]`, but these are simple mock name servers
  implemented in perl; they are generally programmed to misbehave in ways
  `named` wouldn't, so as to exercise `named`'s ability to interoperate with
  badly behaved name servers.  Logs, if any, are captured in `ansX/ans.run`.

All test scripts source the file `bin/tests/system/conf.sh` (which is
generated by `configure` from `conf.sh.in`).  This script provides
functions and variables pointing to the binaries under test; for example,
`DIG` contains the path to `dig` in the build tree being tested, `RNDC`
points to `rndc`, `SIGNZONE` to `dnssec-signzone`, etc.

#### <a name="unittest"></a> Building unit tests

BIND uses the cmocka, unit testing framework.

To build BIND with unit tests, run `configure` with the `--with-cmocka`
option.  This requires cmocka >= 1.0.0 to be installed in the system.

#### Running unit tests

Unit tests are stored in `/tests` subdirectories under the libraries
they test.  For example, the unit tests for libisc are in `lib/isc/tests`.
Particular test sets are called `{module}_test.c`, where {module} is
usually the name of the module being tested; `rbt_test.c` tests functions
in `rbt.c`.  (There are exceptions to this rule, though; for instance,
`hash_test.c` tests hash functions that are implemented in several
different files in `lib/isc`.)

When BIND is built with unit tests, they will be run as part of
`make` `check`.  But if you want to run *only* the ATF unit tests:

        $ sh unit/unittest.sh

You can also run the unit tests for only one library:

        $ cd lib/isc/tests (or lib/dns/tests)
        $ make unit

Or run a particular test case (in the following example, the isc_sha512
test case in the hash unit test).  This has the advantage that you can see
whatever output the unit test emits, whereas in the other modes, output is
redirected:

        $ cd lib/isc/tests
        $ ./hash_test isc_sha512

#### Writing unit tests

Information on writing cmocka tests can be found at the
[cmocka website](https://cmocka.org).

New unit tests should be added whenever new API functionality is added to the
libraries.

### <a name="arch"></a> BIND system architecture

#### <a name="layout"></a> Source tree layout

* `bind9/bin`: binaries
    * `bind9/bin/named`: source code for the `named` binary; includes server configuration, interface manager, client manger, and high-level processing logic for query, update, and xfer.
    * `bind9/bin/dnssec`: DNSSEC-related tools written in C:
      `dnssec-keygen`, `dnssec-signzone`, `dnssec-settime`,
      `dnssec-revoke`, `dnssec-keyfromlabel`, `dnssec-dsfromkey`,
      `dnssec-verify` (BIND 9.9+)
    * `bind9/bin/python` (BIND 9.9+): tools written in python. Currently
       has `dnssec-checkds` and `dnssec-coverage`
    * `bind9/bin/rndc`: `rndc` binary
    * `bind9/bin/dig`: `dig`, `host`, and `nslookup`
    * `bind9/bin/delv`: `delv`
    * `bind9/bin/check`: `named-checkconf` and `named-checkzone`
    * `bind9/bin/confgen`: `rndc-confgen`, `ddns-confgen`, and
      `tsig-keygen` (BIND 9.9+)
    * `bind9/bin/tools`: assorted useful tools: `named-journalprint`,
      `nsec3hash`, etc
* `bind9/lib`: libraries
    * `bind9/lib/isc`: implements basic functionality such as threads,
      tasks, timers, sockets, memory manager, buffers, and basic data types.
        * `bind9/lib/isc/tests`: unit tests for libisc
    * `bind9/lib/dns`: implements higher-level DNS functionality:
      red-black trees, rdatasets, views, zones, ACLs, resolver, validator, etc
        * `bind9/lib/dns/tests`: unit tests for libdns
    * `bind9/lib/bind9`: library implementing bind9-specific functionality,
      principally configuration validity checking (used in `named` and
      `named-checkconf` when reading `named.conf`).
    * `bind9/lib/isccfg`: library implementing the `named.conf`
      configuration parser.
    * `bind9/lib/isccc`: library implementing the control channel used
      by `rndc`
    * `bind9/lib/irs`: provides mechanisms for reading `/etc/resolv.conf`
      and other configuration files.

#### Namespace

See the [namespace](style.md#public_namespace) discussion in the
[BIND coding style](style.md) document.

#### <a name="dbc"></a>Design by contract

BIND uses the "Design by Contract" pattern for most function calls.

A quick summary of the idea is that a function and its caller make a
contract.  If the caller meets certain preconditions, then the function
promises to either fulfill its contract (i.e. guarantee a set of
postconditions), or to clearly fail.

"Clearly fail" means that if the function cannot succeed, then it will
not silently fail and return a value which the caller might interpret as
success.

If a caller doesn't meet the preconditions, then "further execution is
undefined".  The function can crash, compute a garbage result, fail
silently, etc.  Allowing the function to define preconditions greatly
simplifies many APIs, because the API need not specify a way of saying
"hey caller, the values you passed in are garbage".

Typically, preconditions are specified in the functions .h file, and
encoded in its body with `REQUIRE` statements.  The `REQUIRE` statements
cause the program to dump core if they are not true, and can be used to
identify callers that are not meeting their preconditions.

Postconditions can be encoded with `ENSURE` statements.  Within the body of
a function, `INSIST` is used to assert that a particular expression must be
true.

Assertions must not have side effects that the function relies upon,
because assertion checking may be turned off in some environments.
(This is *not* recommended, however: assertion failures serve the
useful function of ensuring that `named` does not continue running
in an insane state.  The surfeit of assertions in BIND 9 have made
it vulnerable over the years to "packets of death" and other
denial-of-service exploits, but as of this writing - more than 14
years since the initial release - BIND 9 has never had an arbitrary
code execution vulnerability.)

#### <a name="magic"></a>Magic numbers

A number of data structures in the ISC and DNS libraries have an
`unsigned int magic` value as the first field.  The purpose of the
magic number is principally to validate that a pointer that's been
passed to a subroutine really points to the type it claims to be.  This
helps detect problems caused by resources being freed prematurely, that
have been corrupted, or that have not been properly initialized.  It can
also be handy in debugging.

Magic numbers should always be the first field in a structure.  They never
require locking to access.  As to the actual value to be used, something
mnemonic is good:

        #define TASK_MAGIC                      0x5441534BU     /* TASK. */
        #define VALID_TASK(t)                   ((t) != NULL && \
                                                 (t)->magic == TASK_MAGIC)

        #define TASK_MANAGER_MAGIC              0x54534B4DU     /* TSKM. */
        #define VALID_MANAGER(m)                ((m) != NULL && \
                                                 (m)->magic ==
                                                  TASK_MANAGER_MAGIC)

Unless the memory cost is critical, most objects should have a magic number.

The magic number should be the last field set in a creation routine, so that
an object will never be stamped with a magic number until it is valid.

The magic number should be set to zero immediately before the object is
freed.

Magic values are usually private to the implementation of the type;
i.e.  they are defined in the .c file, not the .h file.  There are some
exceptions to this.

Validation of magic numbers is done by routines that manipulate the type,
not by users of the type.  (Indeed, user validation is usually not possible
because the magic number is not public.)

#### <a name="results"></a>Result codes

The `isc_result_t` type is provided for function result codes,
and is used throughout BIND.  For example:

        isc_result_t result;
        FILE *fp = NULL;

        result = isc_stdio_open("file", "r", &fp);

Note that an explicit result code is used, instead of mixing the error
result type with the normal result type.  In contrast to the
C library routine `fopen()` which returns a file pointer or `NULL`
on failure (setting `errno` to indicate what the nature of the problem
was), BIND style always keeps indication of the function's success or
failure separate from its returned data.  Similarly, the C library
function `fread()` returns the number of characters read and then
depends on `feof()` and `ferror()` to determine whether an error occured
or the end of file was reached, but BIND's version uses result codes:

        char buffer[BUFSIZ];
        size_t n;

        result = isc_stdio_read(buffer, 1, sizeof(bufer), fp, &n);
        if (result == ISC_R_SUCCESS) {
                /* Do something with 'buffer'. */
        } else if (result == ISC_R_EOF) {
                /* EOF. */
                result = ISC_R_SUCCESS;
        } else {
                /* Some other error occurred. */
        }

Only functions which cannot fail (assuming the caller has provided valid
arguments) should return data directly instead of a result code.  For
example, `dns_name_issubdomain()` returns an `bool`, because it
has no failure mode.

A result code can be converted to a human-readable error message by
calling `isc_result_totext(result)`.

Many result codes have been defined and can be found in the source tree
in header files called `result.h` (for example, the result codes defined
for the ISC library are in `lib/isc/include/isc/result.h`.

ISC library result codes (many of which are generically useful elsewhere)
begin with `ISC_R`: examples inclue `ISC_R_SUCCESS`, `ISC_R_FAILURE`,
`ISC_R_NOMEMORY`, etc. 

DNS library result codes begin with `DNS_R`: `DNS_R_SERVFAIL`, `DNS_R_NXRRSET`,
etc).  Other sets of result codes are defined for crypto functions (`DST_R`
and `PKCS_R`).

For portability, ISC result codes are used instead of codes provided
by the operating system; for example, `ISC_R_NOMEMORY` instead of
`ENOMEM`.  In some cases, but not all, POSIX-defined error codes can be
converted to an ISC result code by calling `isc__errno2result(errno)`.
This can't be relied on; there are too many OS-specific error codes to
provide meaningful translations for all of them.  Unknown `errno` values
are converted to `ISC_R_UNEXPECTED`.

#### <a name="buffers">Buffers and regions

A useful set of functions is provided for manipulating memory
buffers: the `isc_buffer` API.  Buffers can be used for parsing
and constructing messages in both text and binary formats.

A buffer is associated with a region of memory, which is subdivided
into 'used' and 'available'.  The 'used' subregion is further subdivided
into 'consumed' and 'remaining'.

When parsing a message, the message to be parsed in in the 'used'
part of the buffer.  As the message is parsed, the 'consumed'
subregion grows and the 'remaining' subregion shrinks. 

When creating a message, data is written into the 'available'
subregion, which then becomes part of 'used'.

The current sizes of these subregions can be determined by calling
`isc_buffer_usedlength()`, `isc_buffer_consumedlength()`,
`isc_buffer_remaininglength()`, and `isc_buffer_availablelength()`.

The memory associated with a buffer may be dynamically allocated
from a memory context using `isc_buffer_allocate()` and freed by
`isc_buffer_free()`, or it may be a static region of memory
with which we want to use buffer semantics.  In that case, we
associate a new buffer object with the desired block of memory
by running `isc_buffer_init()`.  If the intention is to write
to the memory, nothing further is necessary; if it is to read
the memory using buffer sementaics, then we must mark the memory
as part of the 'used' subregion:

        isc_buffer_t b;
        char text[BUFSIZ];
        unsigned int n;

        result = isc_stdio_read(buf, 1, BUFSIZ, fp, &n);
        if (result == ISC_R_SUCCESS && n > 0U) {
                isc_buffer_init(&b, text, sizeof(text));
                isc_buffer_add(&b, n);
                /* now we can read the buffer */
        }

Several functions are provided for both reading and writing
to the buffer:

* `isc_buffer_getuint8()`: Read and return an 8-bit unsigned integer
* `isc_buffer_putuint8()`: Write an 8-bit unsigned integer to a buffer

* `isc_buffer_getuint16()`: Read a 16-bit unsigned integer in
  network byte order, convert to host byte order, and return it
* `isc_buffer_putuint16()`: Convert an unsigned 16-bit integer from
  host to network byte order and write it to a buffer.

* `isc_buffer_getuint32()`: Read a 32-bit unsigned integer in
  network byte order, convert to host byte order, and return it
* `isc_buffer_putuint32()`: Convert an unsigned 32-bit integer from
  host to network byte order and write it to a buffer.

* `isc_buffer_putstr()`: Copy a null-terminated string into a buffer
* `isc_buffer_putmem()`: Copy a fixed-length region of memory into a
  buffer.

A simpler set of functions have also been provided for handling
memory regions: the `isc_region` API.  A region is a simple structure
that only contains a base pointer (to the beginning of the associated
memory) and a length.  Buffers and buffer subregions can be converted to
regions using `isc_buffer_region()`, `isc_buffer_usedregion()`, etc.
Regions can be copied to buffers by using `isc_buffer_copyregion()`,
or simply by running `isc_buffer_init()` on the region's base pointer.

#### <a name="mem"></a>Memory management

BIND manages its own memory internally via "memory contexts".  Multiple
separate memory contexts can be created for the use of different modules or
subcomponents, and each can have its own size limits and tuning parameters
and maintain its own statistics, allocations and free lists.

The memory system helps with diagnosis of common coding errors such as
memory leaks and use after free. Newly allocated memory is populated with
the repeating value 0xbe, and freed memory with 0xde.  BIND tracks every
memory allocation, and will complain (via an assertion failure) if any
memory has not been freed when BIND shuts down.

To create a basic memory context, use:

        isc_mem_t *mctx = NULL;
        isc_mem_create(&mctx);

(The zeroes are tuning parameters, `max_size` and `target_size`: Any
allocations smaller than `max_size` will be satisfied by getting
blocks of size `target_size` from the operating system's memory
allocator and breaking them up into pieces, while larger allocations
will call the system allocator directly. These parameters are rarely
used.)

When holding a persistent reference to a memory context it is advisable to
increment its reference counter using `isc_mem_attach()`.  Do not just
copy an `mctx` pointer; this may lead to a shutdown race in which the
memory context is freed before all references have been cleaned up.

        /*
         * Function to create an 'isc_foo' object.
         */
        isc_result_t
        isc_foo_create(isc_mem_t *mctx, isc_foo_t **foop) {
                isc_foo_t *foo;

                REQUIRE(mctx != NULL);
                REQUIRE(foop != NULL && *foop == NULL);

                foo = isc_mem_get(mctx, sizeof(isc_foo_t))

                /* Attach to memory context */
                isc_mem_attach(mctx, &foo->mctx);

                /* Populate other isc_foo members here */

                foo->magic = ISC_FOO_MAGIC;
                
                *foop = foo;
                return (ISC_R_SUCCESS);
        }

When finished with a memory context, detach it with `isc_mem_detach()`.
If freeing an object that contains a reference to a memory context,
you free it and detach its reference at the same time using
`isc_mem_putanddetach()`.

        void
        isc_foo_destroy(isc_foo_t **foop) {
                isc_foo_t *foo = *foop;

                /* clean up various isc_foo members */
                foo->magic = 0;

                isc_mem_putanddetach(&foo->mctx, foo, sizeof(isc_foo_t));

                *foop = NULL;
        }

Two sets of allocation and deallocation functions are provided:
`isc_mem_get()` and `isc_mem_put()`; and `isc_mem_allocate()` and
`isc_mem_free()`.

The call to `isc_mem_put()` must specify the number of bytes being freed,
so use `isc_mem_get()` when the caller can easily keep track of the size of
the allocation.

A call to `isc_mem_free()` does not need to specify the size of the
allocation, it simply frees whatever was allocated at that address, so use
`isc_mem_allocate()` when use variable size blocks of memory.

The function `isc_mem_strdup()` -- a version of `strdup()` that uses memory
contexts -- will also return memory that can be freed with
`isc_mem_free()`.

Every allocation and deallocation requires a memory context lock to be
acquired.  This will cause performance problems if you write code that
allocates and deallocates memory frequently.  Whenever possible,
inner loop functions should be passed static buffers rather than allocating
memory.

In cases where small fixed-size blocks of memory may be needed frequently,
the `isc_mempool` API can be used.  This creates a standing pool of blocks
of a specified size which can be passed out and returned without the need
for locking the entire memory context.

#### <a name="lists"></a>Lists

A set of macros are provided for creating, modifying and iterating
doubly-linked lists.  These are defined in `<isc/list.h>`.

To create a structure that will be part of a linked list, specify
an `ISC_LINK` as one of its members:

        typedef struct isc_foo isc_foo_t;
        struct isc_foo {
                unsigned int magic;

                /* other contents */

                ISC_LINK(isc_foo_t) link;
        };

(Note the `typedef` of `isc_foo_t` prior to the structure declaration.)

When creating an instance of this structure, initialize the link:

        isc_result_t
        isc_foo_create(isc_mem_t mctx, isc_foo_t **foop) {
                isc_foo_t *foo;

                REQUIRE(foop != NULL && *foop == NULL);

                foo = isc_mem_get(mctx, sizeof(isc_foo_t));

                ISC_LINK_INIT(foo, link);

                /* initialize other members */

                foo->magic = ISC_FOO_MAGIC;
                *foop = foo;
                return (ISC_R_SUCCESS);
        }

To make a list of these elements, first create a list variable
by declaring it using the `ISC_LIST` macro, then initialize it
with `ISC_LIST_INIT`:

        ISC_LIST(isc_foo_t) foolist;
        ISC_LIST_INIT(foolist);

The list can then be modified:

        ISC_LIST_APPEND(foolist, foo1, link);

Several macros are provided for this purpose, including `ISC_LIST_PREPEND`,
`ISC_LIST_INSERTBEFORE`, and `ISC_LIST_INSERTAFTER`.

More macros are provided for iterating the list:

        isc_foo_t *foo;
        for (foo = ISC_LIST_HEAD(foolist);
             foo != NULL; 
             foo = ISC_LIST_NEXT(foo, link))
        {
                /* do things */
        }

There are also `ISC_LIST_TAIL` and `ISC_LIST_PREV` macros for walking the
list in reverse order.

Items can be removed from the list using `ISC_LIST_UNLINK`:

        ISC_LIST_UNLINK(foolist, foo, link);

#### <a name="names"></a>Names

The `dns_name` API has facilities for processing DNS names and labels,
both dynamically and statically allocated, relative and absolute,
compressed and not, with straightforward conversions from text to
wire format and vice versa.

##### Initializing

When a name object is initialized, a pointer to an "offset table"
(`dns_offsets_t`) may optionally be supplied; this will improve
performance of most name operations if the name is used more than
once.

        dns_name_t name1, name2;
        dns_offsets_t offsets1;

        dns_name_init(&name1, &offsets1);
        dns_name_init(&name2, NULL);

##### Copying

There are two methods for copying name objects: `dns_name_clone()`
makes a target refer to the same data as the source without copying
the data, so the source must not be changed while the target is still in
use.  `dns_name_dup()` and `dns_name_dupwithoffsets()` create a true
copy of the name, dynamically allocating memory as needed; targets
created by these must be freed by calling `dns_name_free()`.

##### Wire format

To create a name object from a wire format message such as a DNS
query or response, use `dns_name_fromwire()`.  Generally this is
done with names in a DNS message object (`dns_message_t`), and some
names may be compressed; the ongoing decompression state for a message
is maintained in a "decompression context" object (`dns_decompress_t`)
which must be initialized before the first call to `dns_name_fromwire()`
for a given message, and passed to each additional call until all
the names have been extracted.

Similarly, `dns_name_towire()` converts name objects into DNS wire
format, using an ongoing "compression context" object (`dns_compress_t`).

##### Text format

Converting text representations of names to name objects is
usually done by calling `dns_name_fromtext()`, which converts a name
found in a source [buffer object](#buffers)

When using `dns_name_fromtext()`, the target name must have a buffer
associated with it, or else a buffer must be passed in separately which
will be used to store name data.  An `origin` parameter indicates a zone origin
name, which is appended to the converted name; for absolute names, the root
zone name, `dns_rootname`, should be used as origin.  If the
`DNS_NAME_DOWNCASE` flag is set in the `options` parameter, then the target
name will be converted to lower case, regardless of the case of the source
name.

        char *text = "foo.com";
        unsigned char namedata[DNS_NAME_MAXWIRE];
        isc_buffer_t buf;
        dns_name_t name;

        dns_name_init(&name, NULL);
        isc_buffer_init(&buf, namedata, sizeof(namedata));
        isc_buffer_add(&buf, strlen(text));
        result = dns_name_fromtext(&name, &buf, dns_rootname, 0, NULL);
        if (result != ISC_R_SUCCESS) {
                /* something went wrong */
        }

An alternate mechanism `dns_name_fromstring()` converts a standard
null-terminated string to a name object.  When using this function,
if the target name has a buffer associated with it, then that buffer
is used for the resulting name data; otherwise, memory is allocated for
the purpose and the name will need to be freed with `dns_name_free()`
later.

There are also multiple functions for converting name objects to text.
`dns_name_tostring()` writes the name into a buffer object, which must
have at least `DNS_NAME_MAXTEXT` bytes of available space.
`dns_name_format()` writes the name into a null-terminated
string, which must have space for at least `DNS_NAME_FORMATSIZE`
bytes.  `dns_name_tostring()` allocates memory for the text, which
must later be freed with `isc_mem_free()`.

##### Manipulating names

Several functions are provided for inspecting and modifying name objects.
These include:

* `dns_name_countlabels()` returns the number of labels in a name.
* `dns_name_getlabel()` locates a specified label in a name
  and references it in a [region object](#buffers).  In the name
  "www.example.com", label 0 is "www", label 1 is "example",
  label 2 is "com", and label 3 is the root zone.
* `dns_name_getlabelsequence` copies a specified label and a
  specified number of labels after it into a new name object.
* `dns_name_split()` separates a name into prefix and a suffix
  on a specified label boundary.  For example, "www.example.com"
  can be split into "www" and "example.com".
* `dns_name_concatenate()` concatenates a prefix and a suffix into
  a single name.

##### Comparisons

DNS name comparisons are more complex than simple string comparisons.  When
sorting names, labels at the end of the name are more significant than
labels at the beginning ("zzz.com" is less than "aaa.zzz.com").
Furthermore, it's necessary to determine relationships between names other
than simple ordering:  Whether one name is the ancestor of another, or
whether they share a common ancestor, and if so how many labels they
have in common.  The `dns_name_fullcompare()` function determines these
things.  Its return value is the relationship between two names:

        dns_namereln_t rel;
        unsigned int common;
        int order;

        /*
         * Get relationship between two names; store the sort
         * order in 'order' and the number of common labels in
         * 'common'
         */
        rel = dns_name_fullcompare(name1, name2, &order, &common);

The return value may be:

* `dns_namereln_contains`: name1 contains name2
* `dns_namereln_subdomain`: name2 contains name1
* `dns_name_commonancestor`: name1 and name2 share some labels
* `dns_name_equal`: name1 and name2 are the same

Some simpler comparison functions are provided for convenience when 
not all of this information is required:

* `dns_name_compare()`: returns the sort order of two names but
  not their relationship
* `dns_name_equal()`: returns `true` when names are equivalent
* `dns_name_caseequal()`: same as `dns_name_equal()`, but case-sensitive
* `dns_name_issubdomain()`: returns `true` if one name contains another

##### Fixed names

`dns_fixedname_t` is a convenience type containing a name, an offsets
table, and a dedicated buffer big enough for the longest possible DNS
name.  This allows names to be stack-allocated with minimal initialization:

        dns_fixedname_t fn;
        dns_name_t *name;

        name = dns_fixedname_initname(&fn);

`name` is now a pointer to a `dns_name` object in which a name can be
stored for the duration of this function; there is no need to initialize,
allocate, or free memory.

#### <a name="rdata"></a>Rdata Classes

##### Rdataset

An rdataset (`dns_rdataset_t`) is BIND's representation of a DNS RRset,
excluding the owner name but including the type, TTL, and the contents of
each RR. The rdataset object does not hold the data itself: it is a view
that refers to data held elsewhere -- for example, in a DNS message, or in
an rbtdb (for cached or authoritative data).

It is a vaguely object-oriented polymorphic data structure, with different
implementations depending on the backing data structure that actually holds
the records. The rdataset is explicitly associated/disassociated with the
backing data structure so that it can maintain reference counts.

One important rdataset implementation is part of the red-black tree
database, implemented in `rdata.c`.

##### Rdatalist

Another backing data structure for an rdataset is the rdatalist
(`dns_rdatalist_t`) -- a linked list of rdata structures.  An rdatalist is
used to record the locations of records in a DNS message. It does not
maintain reference counts.  An rdatalist can be converted to or from an
rdataset using `dns_rdatalist_tordataset()` and
`dns_rdatalist_fromrdataset()`.

##### Rdata

See the [RRATA Types](rdata.md) document for details on type-specific
rdata conversions.

#### <a name="iterators"></a>Iterators

Retrieving data from BIND databases involves the use of iterator
functions to walk from entry to entry.  Several iterator function
sets have been defined:

* `dns_dbiterator`: Walks the nodes in a database
* `dns_rdatasetiter`: Walks the RRsets in a node
* `dns_rdataset`: Walks the resource records in an RRset
* `dns_rriterator`: A combination of the previous three; walks all
   the RRs or RRsets in a database
* `dns_rbtnodechain`: Walks the nodes in a red-black tree

Each of these has a `first()`, `next()` and `current()` function; for
example, `dns_rdataset_first()`, `dns_rdataset_next()`, and
`dns_rdataset_current()`. 

The `first()` and `next()` functions move the iterator's cursor and so that
the data at a new location can be retrieved.  (Most of these can only step
by one item at a time, but `dns_rriterator` provides both `next()` and
`nextrrset()`, enabling it to step by RR or RRset.)  These functions return
`isc_result_t`, with `ISC_R_SUCCESS` indicating that there is data to
retrieve and `ISC_R_NOMORE` indicating that the iterator is finished.

The `current()` function has no return value; it simply retrieves the
data at the current cursor location.

To use an iterator, call the `first()` function, then the `current()`
function, then loop over the `next()` function until it no longer returns
success:

        for (result = dns_rdataset_first(rdataset);
             result == ISC_R_SUCCESS;
             result = dns_rdataset_next(rdataset))
        {
                dns_rdata_t rdata = DNS_RDATA_INIT;
                dns_rdataset_current(rdataset, &rdata);
                /* rdata is now populated with an RR */
        }

In some cases, calling an iterator function causes the acquisition of
database and/or node locks.  Rather than reaquire these locks every time
one of these functions is called, they are often simply held until the
iterator is destroyed.  If a caller wishes to hold an iterator open but not
use it for a while, it should call the iterator's `pause()` function (such
as `dns_dbiterator_pause()`); this will release all the locks that are
currently held by the iterator so that other threads may proceed.

#### <a name="logging"></a>Logging

The ISC logging system is designed to provide a flexible, extensible
method of writing messages, either to the system's logging facility,
directly to a file, or into the bitbucket -- usually configured per
the desires of the user of the program.

Each log message is associated with a particular category (eg, "security"
or "database") that reflects its nature, and a particular module (such as
the library's source file) that reflects its origin.  Messages are also
assigned a priority level which states how remarkable the message is;
the program's user may use this to decide how much detail is desired.

Libraries which use the ISC logging system can be linked against each
other without fear of conflict.  A program is able to select which, if
any, libraries will write log messages.

##### Fundamentals

Log messages are associated with three pieces of information that are
used to determine their disposition:  a category, a module, and a
level (aka "priority").

A category describes the conceptual nature of the message, that is,
what general aspect of the code it is concerned with.  For example,
the DNS library defines categories that include the workings of the
database as well security issues.  Macros for naming categories are
typically provided in the library's log header file, such as
`DNS_LOGCATEGORY_DATABASE` and `DNS_LOGCATEGORY_SECURITY` in `<dns/log.h>`.
The special category `ISC_LOGCATEGORY_DEFAULT` is associated with
any message that does not match a particular category (or matches a
category but not a module, as seen in the next paragraph).

A module is loosely the origin of a message.  There may not be a
one-to-one correspondence of source files with modules, but it is typical
that a module's name reflect the source file in which it is used.  So, for
example, the module identifier `DNS_LOGMODULE_RBT` would be used by
messages coming from within the `lib/dns/rbt.c` source file.

The specification of the combination of a category and a module for a
message are called the message's "category/module pair".

The level of a message is an indication of its severity.  There are
six standard logging levels, in order here from most to least severe
(least to most common):

* `ISC_LOG_CRITICAL`: An error so severe it causes the program to exit.
* `ISC_LOG_ERROR`: A very notable error, but the program can go on.
* `ISC_LOG_WARNING`: Something is probably not as it should be.
* `ISC_LOG_NOTICE`: Notable events that occur while the program runs.
* `ISC_LOG_INFO`: Statistics and routine announcements.
* `ISC_LOG_DEBUG(unsigned int level)`: Detailed debugging messages.

`ISC_LOG_DEBUG` is not quite like the others in that it takes an
argument the defines roughly how detailed the message is; a higher
level means more copious detail, so that values near 0 would be used
at places like the entry to major sections of code, while greater
numbers would be used inside loops.

The next building block of the logging system is a channel.  A channel
specifies where a message of a particular priority level should go, as
well as any special options for that destination.  There are four
basic destinations, as follows:

* `ISC_LOG_TOSYSLOG`: Send it to syslog.
* `ISC_LOG_TOFILE`: Write to a file.
* `ISC_LOG_TOFILEDESC`: Write to a (previously opened) file descriptor.
* `ISC_LOG_TONULL`: Do not write the message when selected.

A file destination names a path to a log file.  It also specifies the
maximum allowable byte size of the file before it is closed (where 0
means no limit) and the number of versions of a file to keep (where
`ISC_LOG_ROLLNEVER` means the logging system never renames the log file,
and `ISC_LOG_ROLLINFINITE` means no cap, other than integer size, on the
number of versions).  Version control is done just before a file is opened,
so a program that used it would start with a fresh log file (unless using
`ISC_LOG_ROLLNEVER`) each time it ran.  If you want to use an external
rolling method, use `ISC_LOG_ROLLNEVER` and ensure that your program has a
mechanism for calling `isc_log_closefilelogs()`.

A file descriptor destination is simply associated with a previously
opened stdio file descriptor.  This is mostly used for associating
stdout or stderr with log messages, but could also be used, for
example, to send logging messages down a pipe that has been opened by
the program.  File descriptor destinations are never closed, have no
maximum size limit, and do not do version control.

Syslog destinations are associated with the standard syslog facilities
available on your system: generally `syslogd` on UNIX and Linux systems
and the Application log in the Event Viewer on Windows systems.  They too
have no maximum size limit and do no version control.

Since null channels go nowhere, no additional destination
specification is necessary.

Channels have string names that are their primary external reference.
There are four predefined logging channels (five, as of BIND 9.11):

* `"default_stderr"`: Descriptor channel to stderr at priority `ISC_LOG_INFO`
* `"default_logfile"`: File channel created if the user specifies a logfile using `named -L` at priority `ISC_LOG_DYNAMIC` (9.11 and higher only)
* `"default_debug"`: Descriptor channel to stderr at priority `ISC_LOG_DYNAMIC`
* `"default_syslog"` -- Syslog channel to `LOG_DAEMON` at priority `ISC_LOG_INFO`
* `"null"`           -- Null channel

Other channels may be configured by the user via `named.conf`.

`ISC_LOG_DYNAMIC` indicates to the logging system that
debugging messages are desired, but only at the current debugging level
of the program.  The debugging level can be modifid dynamically at
runtime; in `named` this can be done by the `"rndc trace"` command.
When the debugging level is 0 (turned off), then no debugging messages are
written to the channel.  If the debugging level is raised, only debugging
messages up to the current debugging level are written to the channel.

These objects -- the category, module, and channel -- direct hessages
to desired destinations.  Each category/module pair can be associated
with a specific channel, and the correct destination will be used 
when a message is logged by `isc_log_write()`.

In `isc_log_write()`, the logging system first looks up a list that
consists of all of the channels associated with a particular category.
It walks down the list looking for each channel that also has the
indicated module associated with it, and writes the message to each
channel it encounters.  If no match is found in the list for the
module, the default channel (associated with `ISC_LOGCATEGORY_DEFAULT`)
is used.  The default is also used if no channels have been specified
for the category at all.

##### Externally visible structure

The types used by programs for configuring log message destinations are
`isc_log_t` and `isc_logconfig_t`.  The `isc_log_t` type is normally
created only once by a program, to hold static information about what
categories and modules exist in the program and some other housekeeping
information.  `isc_logconfig_t` is used to store the configurable
specification of message destinations, which can be changed during the
course of the program.

A starting configuration (`isc_logconfig_t`) is created implicitly when
the context (`isc_log_t`) is created.  The pointer to this configuration
is returned via a parameter to `isc_log_create()` so that it can then be
configured.  A new log configuration can be established by creating
it with `isc_logconfig_create()`, configuring it, then installing it as
the active configuration with `isc_logconfig_use()`.

##### Logging in multithreaded programs

The entire logging context is thread-locked for most of the duration of the
`isc_log_write()`.   However, `isc_log_write()` avoids the delays caused by
locking when it is clear that there are no possible outputs for a message
based on its debugging level --- this is so that a program can have
debugging messages sprinkled liberally throughout it but not incur any
locking penalty when debugging is not enabled.

##### Using libraries that use the logging system

To enable the messages from a library that uses the logging system,
the following steps need to be taken to initialize it.

1. Include the main logging header file as well as the logging header
   file for any additional library you are using.  For example, when using
   the DNS library, include the following:

        #include <isc/log.h>
        #include <dns/log.h>

1. Initialize a logging context.  A logging context needs a valid
   memory context in order to work, so the following code snippet shows a
   rudimentary initialization of both.

        isc_mem_t *mctx;
        isc_log_t *lctx;
        isc_logconfig_t *lcfg;

        isc_mem_create(&mctx);
        if (isc_log_create(mctx, &lctx, &lcfg) != ISC_R_SUCCESS)) {
                oops_it_didnt_work();
        }

1. Initalize any additional libraries.  The convention for the name of
   the initialization function is `{library}_log_init()`, with a pointer to
   the logging context as an argument.  The function can only be called
   once in a program or it will generate an assertion.

        `dns_log_init(lctx);`

   If you do not want a library to write any log messages, simply do not
   call its the initialization function.

1. Create any channels you want in addition to the internal channels
   of `default_syslog`, `default_stderr`, `default_debug` and null.  A
   destination structure needs to be filled for any destination other than
   null.  The following examples show use of a file log, a file descriptor
   log, and syslog.

        isc_logdestination_t destination;

        destination.file.name = "/var/log/example";
        destination.file.maximum_size = 0;              /* No byte limit. */
        destination.file.versions = ISC_LOG_ROLLNEVER;  /* External rolling. */
        result = isc_log_createchannel(lcfg, "sample1", ISC_LOG_TOFILE,
                                       ISC_LOG_DYNAMIC, &destination,
                                        ISC_LOG_PRINTTIME);
        if (result != ISC_R_SUCCESS)
                oops_it_didnt_work();

        destination.file.stream = stdout;
        result = isc_log_createchannel(lcfg, "sample2", ISC_LOG_TOFILEDESC,
                                       ISC_LOG_INFO, &destination,
                                       ISC_LOG_PRINTTIME);
        if (result != ISC_R_SUCCESS)
                oops_it_didnt_work();

        destination.facility = LOG_ERR;
        result = isc_log_createchannel(lcfg, "sample3", ISC_LOG_SYSLOG,
                                       ISC_LOG_ERROR, &destination, 0);
        if (result != ISC_R_SUCCESS)
                oops_it_didnt_work();

   `ISC_LOG_DYNAMIC` is used to define a channel that wants any of the
   messages up to the current debugging level of the program.
   `ISC_LOG_DEBUG(level)` can define a channel that *always* gets messages
   up to the debug level specified, regardless of the debugging state of
   the server.

1. Direct the various log categories and modules to the desired
   destination.  This step is not necessary if the normal behavior of
   sending all messages to `default_stderr` is acceptable.  The following
   examples sends DNS security messages to stderr, DNS database messages to
   null, and all other messages to syslog.

        result = isc_log_usechannel(lcfg, "default_stderr",
                                    DNS_LOGCATEGORY_SECURITY, NULL);
        if (result != ISC_R_SUCCESS)
                oops_it_didnt_work();

        result = isc_log_usechannel(lcfg, "null",
                                    DNS_LOGCATEGORY_DATABASE, NULL);
        if (result != ISC_R_SUCCESS)
                oops_it_didnt_work();

        result = isc_log_usechannel(lcfg, "default_syslog",
                                    ISC_LOGCATEGORY_DEFAULT, NULL);
        if (result != ISC_R_SUCCESS)
                oops_it_didnt_work();

   Providing a NULL argument for the category means "associate the channel
   with the indicated module in all known categories":
   `ISC_CATEGORY_DEFAULT`.

   Providing a NULL argument for the module means "associate the channel
   with all modules that use this category."

There are three additional functions you might find useful in your program
to control logging behavior, two to work with the debugging level and one
to control the closing of log files.

        void isc_log_setdebuglevel(isc_log_t *lctx, unsigned int level);
        unsigned int isc_log_getdebuglevel(isc_log_t *lctx);
        
These set and retrieve the current debugging level of the program.
`isc_log_getdebuglevel()` can be used so that you need not keep track of
the level yourself in another variable.

        void isc_log_closefilelogs(isc_log_t *lcxt);

This function closes any open log files.  This is useful for programs that
do not want to do file rotation as with the internal rolling mechanism.
For example, a program that wanted to keep daily logs would define a
channel which used `ISC_LOG_ROLLNEVER`, then once a day would rename the
log file and call `isc_log_closefilelogs()`.  The next time a message needs
to be written a file that has been closed, it is reopened.

#### <a name="rrtype"></a>Adding a new RR type

##### Overview

BIND 9 was designed to make it relatively easy for anyone with sufficient
knowledge of C to add user defined resource record (RR) types.

The descriptions of all the record types known to BIND are in a directory
structure under lib/dns/rdata in the source tree.  This directory is
structured at the first level by the DNS CLASS the record type belongs to.
The name of the directory is the `{class}_{code}` (for example, IN is
`in_1`).

The currently existing classes are `in_1`, `ch_3`, `hs_4`, `any_255` and
`generic` -- the first four hold RR types that are specific to a particular
class, and "generic" holds RR types that are the same across all classes.
Within each of these directories there are pairs of files which describe
the actual types.  These files are named `{type}_{code}.c` and
`{type}_{code}.h`: for examle, the description of the MX record, which has
the RR type code 15, is in `mx_15.c` and `mx_15.h`.

Within each of these files there are method functions for various
operations that apply to types, such as how to print out a type, how to
read a type from a text file, how to read a record from a DNS message in
wire format, etc.  These methods have names constructed from the type,
class (if the record is class specific) and operation to be performed.
These methods are called from the `dns_rdata_{method}` functions which are
declared in `<dns/rdata.h>`.

Once the two files containing the method and type definitions for the
structures have been written you need to run `"make clean"` then `"make"` to
incorporate the new record type.  This will cause the `lib/dns/rdata`
directory structure to be scanned and header files to be rebuilt which will
include the new files.  All the tools that are part of BIND will know about
the new type.

You can also define auxiliary functions to help walk the structure returned
by `dns_rdata_tostruct()`, such as `dns_rdata_txt_first()` and
`dns_rdata_txt_next()`, which are used to walk the text strings in a TXT
record.  The code goes into the .c file and the function prototype into the
.h file the contents of which are included in `<dns/rdatastruct.h>`.

`lib/dns/rdata/generic/proforma.c` and `lib/dns/rdata/generic/proforma.h`
can be copied and used as starting points when defining a adding a new type.
Please also look as the existing record types for examples of how to
implement a method.

##### Type value selection

Type values range from 0 to 65536.   These have been further divided into
reserved values,  values that have global definition and values that have
local definition as defined in [RFC 6895](http://tools.ietf.org/html/rfc6895).
Please use an appropriate value.  You can use a private value
(65280 - 65534) while waiting for a type assignment to be made, then
rename the file and update the type values when the assignment has been
made.

##### Methods

"fromtext" reads a series of tokens from `lexer` and constructs
a DNS record in wire format, which it stores in `target`.  It performs
sanity checks on the entered content, rejecting any invalid records.

        static isc_result_t
        fromtext[_<class>]_<type>(int rdclass, dns_rdatatype_t type,
                                  isc_lex_t *lexer, dns_name_t *origin,
                                  unsigned int options, isc_buffer_t *target,
                                  dns_rdatacallbacks_t *callbacks);


        static isc_result_t
        totext[_<class>]_<type>(dns_rdata_t *rdata,
                                dns_rdata_textctx_t *tctx,
                                isc_buffer_t *target);

"totext" takes a record in wire format, converts it to
presentation format, and stores it in a buffer for later printing.

        static isc_result_t
        fromwire[_<class>]_<type>(int rdclass, dns_rdatatype_t type,
                                  isc_buffer_t *source,
                                  dns_decompress_t *dctx,
                                  unsigned int options,
                                  isc_buffer_t *target_t);

"fromwire" copies in a record received in a DNS message.
It performs sanity checks to ensure that the record conforms to the
specification for the RR type.  It expands any compressed domain names,
and copies out the expanded record to a buffer.
(NOTE: It is critical to the security of the name server that only valid
records are accepted by this function, as other parts of the name server
do not verify the contents of incoming records.)

        static isc_result_t
        towire[_<class>]_<type>(dns_rdata_t *rdata, dns_compress_t *cctx,
                                isc_buffer_t *target);

"towire" takes a record in wire format and adds it to a DNS
message, optionally compressing domain names if that is allowed by the
type's definition.   (NOTE: Compression is no longer allowed in new
RR types, so this is effectively a wrapper around `memmove()`.)

        static int
        compare[_<class>]_<type>(const dns_rdata_t *rdata1,
                                 const dns_rdata_t *rdata2);

"compare" takes two records and compares them according to the
DNSSEC ordering rules.  For all new record types, this is effectively a
wrapper around `memcmp()`.

        static isc_result_t
        fromstruct[_<class>]_<type>(int rdclass, dns_rdatatype_t type,
                                    void *source, isc_buffer_t *target);

"fromstruct" takes a C structure (as described in
`tostruct()`, below) and turns it into a record in wire format.

        static isc_result_t
        tostruct[_<class>]_<type>(dns_rdata_t *rdata, void *target,
                                  isc_mem_t *mctx);

"tostruct" take a record in wire format and breaks it down into
a type-specific C structure defined in the header file.  The name of this
structure is `dns_rdata_<type>[_<class>]_t`; the first element of
the structure must be `"dns_rdatacommon_t common;"`.
If no memory context is passed in, then the caller will preserve the
contents of the record in wire form until the structure is freed or no
longer in use.  If a memory context is passed, in then memory should
be allocated for anything not directly part of the structure.

        static void
        freestruct[_<class>]_<type>(void *source);

"freestruct" frees any memory allocated by `tostruct()`.

        static isc_result_t
        additional[_<class>]_<type>(dns_rdata_t *rdata,
                                    dns_additionaldatafunc_t add,
                                    void *arg);

"additional" provides the ability to add related records
to the additional section of a message when this record is added to
a message. An empty method is usual here.

        static isc_result_t
        digest[_<class>]_<type>(dns_rdata_t *rdata,
                                dns_digestfunc_t digest,
                                void *arg);

"digest" passes the record contents to the `digest` function,
performing any needed DNSSEC canonicalisation.  For all new record types,
this simply involves adding the entire record to a region and passing that
to `digest`, because new record types are treated as opaque blobs of data
by DNSSEC.

        static bool
        checkowner[_<class>]_<type>(dns_name_t *name,
                                    dns_rdataclass_t rdclass,
                                    dns_rdatatype_t type,
                                    bool wildcard);

"checkowner" takes the owner name of the record and checks
that it meets appropriate rules that are defined external to the DNS.
In most cases this can just be a function that returns `true`.

        static bool
        checknames[_<class>]_<type>(dns_rdata_t *rdata,
                                    dns_name_t *owner,
                                    dns_name_t *bad);

"checknames" checks the contents of the rdata with the given
owner name to ensure that it meets externally defined syntax rules.
If `false` is returned, then `bad` will point to the name that
caused the probelm.

        static int
        casecompare[_<class>]_<type>(const dns_rdata_t *rdata1,
                                     const dns_rdata_t *rdata2);

"casecompare" compares two rdatas case-insensitively.
In nearly all cases, this is simply a wrapper around the `compare()`
function, except where DNSSEC comparisons are specified as
case-sensitive. Unknown RR types are always compared case-sensitively.

#### <a name="tasks"></a>Task and timer model

The BIND task/timer management system can be thought of as comparable to a
simple non-preemptive multitasking operating system.

In this model, what BIND calls a "task" (or an `isc_task_t` object) is the
equivalent of what is usually called a "process" in an operating system:
a persistent execution context in which functions run when action is
required.  When the action is complete, the task goes to sleep, and
wakes up again when more work arrives.  A "worker thread" is comparable
to an operating system's CPU; when a task is ready to run, a worker
thread will run it.  By default, BIND creates one worker thread for each
system CPU.

An "event" object can be associated with a task, and triggered when a a
specific condition occurs.  Each event object contains a pointer to a
specific function and arguments to be passed to it.  When the event
triggers, the task is placed onto a "ready queue" in the task manager.  As
each running task finishes, the worker threads pull new tasks off the ready
queue.  When the task associated with a given event reaches the head of the
queue, the specified function will be called.

Examples:

`isc_socket_recv()` calls the `recv()` system call asynchronously: rather
than waiting for data, it returns immediately, but it sets up an event to
be triggered when the `recv()` call completes; BIND can now do other work
instead of waiting for I/O.  Once the `recv()` is finished, the
associated event is triggered.


        /*
         * Function to handle a completed recv()
         */
        static void
        recvdone(isc_task_t *task, isc_event_t *event) {
                /* Arguments are in event->ev_arg. */
        }

        ...

        /*
         * Call recv() on socket 'sock', put results into 'region',
         * minimum read size 1, and call recvdone() with NULL as
         * argument.  (Note: 'sock' is already associated with a
         * particular task, so that doesn't need to be specified
         * here.)
         */
        isc_socket_recv(sock, &region, 1, recvdone, NULL);

A timer is set for a specifed time in the future, and the event will
be triggered at that time.

        /*
         * Function to handle a timeout
         */
        static void
        timeout(isc_task_t *task, isc_event_t *event) {
               /* do things */
         }

         ...

         /*
          * Set up a timer in timer manager 'timermgr', to run
          * once, with a NULL expiration time, after 'interval'
          * has passed; it will run the function 'timeout' with
          * 'arg' as its argument in task 'task'.
          */
         isc_timer_t *timer = NULL;
         result = isc_timer_create(timermgr, isc_timertype_once, NULL,
                                   interval, task, timeout, arg, &timer);

An event can also be explicitly triggered via `isc_task_send()`.  

        static void
        do_things(isc_task_t *task, isc_event_t *event) {
                /* this function does things */
        }

        ...

        /*
         * Allocate an event that calls 'do_things' with a 
         * NULL argument, using 'myself' as ev_sender.
         *
         * DNS_EVENT_DOTHINGS must be defined in <dns/events.h>.
         *
         * (Note that 'size' must be specified because there are
         * event objects that inherit from isc_event_t, incorporating
         * common members via the ISC_EVENT_COMMON member and then
         * following them with other members.)
         */
        isc_event_t *event;
        event = isc_event_allocate(mctx, myself, DNS_EVENT_DOTHINGS,
                                   do_things, NULL, sizeof(isc_event_t));
        if (event == NULL)
                return (ISC_R_NOMEMORY);

        ...

        /*
         * Send the allocated event to task 'task'
         */
        isc_task_send(task, event);

#### More...

Further architectural details on BIND to be added here in the future.
