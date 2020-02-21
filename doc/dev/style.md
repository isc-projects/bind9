## BIND 9 Coding Style

BIND 9 is principally written in [C](#cstyle), with some additional code
written in [Python](#pystyle), [Perl](#plstyle) and
[Bourne shell](#shstyle).  Style guidelines for each of these are
below.

### <a name="cstyle"></a>C

#### Compiler

A C11 compiler, library with C11 extensions and POSIX:2001 are assumed.  Feel
free to use any C11 feature, but make sure to provide compatibility shims for
all supported platforms, e.g. Windows MSVC that doesn't support all of the C11
features.

#### Warnings

Given a reasonable set of things to warn about (e.g. -W -Wall for gcc), the goal
is to compile with no warnings.

#### Copyright Notices

Source files with significant content should have a copyright.  The copyright
year(s) should be kept current.

#### Indentation

Use tabs for indentation.  Spaces before statements are only allowed when
needed to line up a continued expression.  In the following example, spaces
used for indentation are indicated with `"_"`:

    	if (i == 0) {
    		printf("this is going to be %s very long %s statement\\n",
    		_______"a", "printf");
    	}

Text editors should be configured with tab-stop set to 8 characters, and
tabs should not be expanded to into spaces.  The following `vim` settings
conform well to BIND 9 C style:

    	set showmatch
    	set showmode
    	set autoindent
    	set expandtab
    
    	filetype plugin on
    	let c_syntax_for_h = 1
    	autocmd FileType c,cc,cpp set cindent
    	autocmd FileType c,cc,cpp set cino=(0:0l1
    	autocmd FileType c,cc,cpp set fo=rotcq
    	autocmd FileType c,cc,cpp set noexpandtab ts=8
    	autocmd FileType python set ts=4 sw=4
    
    	filetype indent on

#### Vertical Whitespace

Vertical whitespace is encouraged for improved code legibility: closely
related statements should be grouped, and then the groups separated with a
single empty line.  There should never be two or more empty lines adjacent
to one another.

#### Line Length

Lines should be no longer than 80 characters, even if it requires violating
indentation rules to make them fit.  Since C11 is assumed, the best way to
deal with strings that extend past column 80 is to break them into two or
more sections separated from each other by a newline and indentation:

    					puts("This string got very far to the "
    					     "right and wrapped.  ANSI "
    					     "catenation rules will turn this "
    					     "into one long string.");

The rule for string formatting can be violated in cases where breaking
the string prevents ability to lookup the string using grep.  Also please
bear in mind that if you are too deeply nested, the code needs refactoring
and not more line breaks.

#### Comments

Comments should be used whenever they improve the readability or
comprehensibility of the code.  Comments describing public functions are
usually in the header file below the function prototype; comments
describing static functions are above the function declaration.

Comments may be single-line or multi-line.  A single-line comment should be
at the end of the line if there is other text on the line, and should start
in the same column as other nearby end-of-line comments.  The comment
should be at the same indentation level as the code it is referring to.

Multi-line comments should start with `"/*"` on a line by itself.
Subsequent lines should have `" *"` lined-up with the `"*"` above.  The end of
the comment should be `" */"` on a line by itself, again with the `"*"`
lined-up with the one above.  Comments should start with a capital letter
and end with a period.

Good:

    	/*
    	 * Private variables.
    	 */
    
    	static int	a	       /* Description of 'a'. */
    	static int	b	       /* Description of 'b'. */
    	static char *	c	       /* Description of 'c'. */


The following lint and lint-like comments should be used where appropriate:

    	/* ARGSUSED */
    	/* FALLTHROUGH */
    	/* NOTREACHED */
    	/* VARARGS */

#### Header files

.h files should not rely on other files having been included.  .h files
should prevent multiple inclusion.  The OS is assumed to prevent multiple
inclusion of its .h files.

The `#pragma once` directive should be used instead of `#ifdef/#define`
combo, and the `#include <config.h>` should not be used anywhere, the
build system ensures that it's the first included file.

A header file defining a public interface is generally placed in the source
tree two levels below the C file that implements the interface.  For
example, the include file defining the interface for `lib/dns/zone.c` is in
`lib/dns/include/dns/zone.h`.  (The second "dns" in the path enables the file
to be included via `"#include <dns/zone.h>"`.)

Public header files should include interface documentation in Doxygen
format.

Private header files, describing interfaces that are for internal use
within a library but not for public use, are kept in the source tree at the
same level as their related C files, and often have `"_p"` in their names,
e.g. `lib/isc/task_p.h`.

Header files that define modules should have a structure like the
following.  Note that `<isc/lang.h>` MUST be included by any public header
file using the ISC_LANG_BEGINDECLS and ISC_LANG_ENDDECLS macros, so the
correct name-mangling happens for function declarations when C++ programs
include the file.  `<isc/lang.h>` SHOULD be included for private header files
or for public files that do not declare any functions.


    	/*
    	 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
    	 *
    	 * This Source Code Form is subject to the terms of the Mozilla Public
    	 * License, v. 2.0. If a copy of the MPL was not distributed with this
    	 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
    	 */
    
    	#pragma once
    
    	/*****
    	 ***** Module Info
    	 *****/
    
    	/*
    	 * (Module name here.)
    	 *
    	 * (One line description here.)
    	 *
    	 * (Extended description and notes here.)
    	 *
    	 * MP:
    	 *	(Information about multiprocessing considerations
    	 *	here, e.g. locking requirements.)
    	 *
    	 * Reliability:
    	 *	(Any reliability concerns should be mentioned here.)
    	 *
    	 * Resources:
    	 *	(A rough guide to how resources are used by this module.)
    	 *
    	 * Security:
    	 *	(Any security issues are discussed here.)
    	 *
    	 * Standards:
    	 *	(Any standards relevant to the module are listed here.)
    	 */
    
    	/***
    	 *** Imports
    	 ***/
    
    	/* #includes here. */
    	#include <isc/lang.h>
    
    	/***
    	 *** Types
    	 ***/
    
    	/* (Type definitions here.) */
    
    	/***
    	 *** Functions
    	 ***/
    	ISC_LANG_BEGINDECLS
    	/* (Function declarations here, with full prototypes.) */
    	ISC_LANG_ENDDECLS

#### Including Interfaces (.h files)

The first file to be included in a C source file must be config.h.  The
config.h file must never be included by any public header file (that is,
any header file that will be installed by `"make install"`).

Try to include only necessary files, not everything under the sun.
Operating-system-specific files should not be included by most modules; if
they are needed, they should be used with `#ifdef` and controlled by
`configure`.

#### Statements

There should be at most one statement per line.  The comma operator should
not be used to form compound statements.

Bad:

    	if (i > 0) {
    		printf("yes\\n"); i = 0; j = 0;
    		x = 4, y *= 2;
    	}

#### Functions

The use of ANSI C function prototypes is required.

The return type of the function should be listed on a line by itself when
specifying the implementation of the function.  The opening curly brace
should occur on the same line as the argument list, unless the argument
list is more than one line long:

    	static inline void
    	func1(int i) {
    		/* whatever */
    	}
    
    	int
    	func2(int first_argument, int next_argument,
    	      int last_argument)
    	{
    		/* whatever */
    	}

To suppress compiler warnings, unused function arguments must be
declared within the function via the `UNUSED()` macro.

In the function body, local variable declarations must be at the beginning
of the function, followed by any `REQUIRE()` statements, then `UNUSED()`
declarations, then all other code, in that order.  These sections should be
separated by blank lines.

#### Curly Braces

Curly Braces do not get their own indentation.

An opening brace does not start a new line.  The statements enclosed by the
braces should not be on the same line as the opening or closing brace.  A
closing brace should be the only thing on the line, unless it's part of an
else clause.

If a controlling statement (e.g., `if`, `while`, or `for`) or a function
header at the start of a block of code is all on one line, then the opening
brace should at the end of that line. If the controlling statement occupies
multiple lines, then the opening brace should be on the next line by itself.

Historically, when a controlling statement such as `if` or `else` had
only a single action associated with it, then BIND style specified that
no bracing was to used around that action.  This has been revised: in
newly added code, braces are now preferred around all control statement
code blocks.  Note that legacy code has not yet been updated to adhere to
this.

Good:

    	static void
    	f(int i) {
    	       if (i > 0) {
    		       printf("yes\\n");
    		       i = 0;
    	       } else {
    		       printf("no\\n");
    	       }
       }

Bad:

    	void f(int i)
    	 {
    	   if(i<0){i=0;printf("was negative\\n");}
    	   if (i == 0)
    	       printf("no\\n");
    	   if (i > 0)
    	     {
    	       printf("yes\\n");
    	       i = 0;
    	     }}

#### Spaces

* DO put a space between operators like `=`, `+`, `==`, etc.
* DO put a space after `,`.
* DO put a space after `;` in a `for` statement.
* DO put spaces after C reserved words such as `if`, `for`, `while`, and `do`.
* DO put a space after `return`, and parenthesize the return value.
* Do NOT put a space between a variable or function name and `(` or `[`.
* Do NOT put a space after the `sizeof` operator name, and DO parenthesize its argument: `malloc(4 * sizeof(long))`.
* Do NOT put a space immediately after a `(` or immediately before a `)`, unless it improves readability.  The same goes for `[` and `]`.
* Do NOT put a space before `++` or `--` when used in post-increment/ decrement mode, or after them when used in pre-increment/decrement mode.
* Do NOT put a space before `;` when terminating a statement or in a `for` statement.
* Do NOT put a space after `*` when used to dereference a pointer, or on either side of `->`.
* Do NOT put a space after `~`.
* The `|` operator may either have a space on both sides or it may have no spaces, depending on readability.  Either way, if the `|` operator is used more than once in a statement, then the spacing must be consistent.

#### Return Values

If a function returns a value, it should be cast to `(void)` if you don't
care what the value is, except for `printf` and its variants, `fputc`,
`fwrite` (when writing text), `fflush`, `memmove`, `memset`, `strcpy`,
`strncpy`, and `strcat`.

Certain functions will return values or not depending on the operating
system or even compiler flags; these include `openlog` and `srandom`.  The
return value of these should not be used nor cast to `(void)`.

All error conditions must be handled.

Mixing of error status and valid results within a single type should be
avoided.

Good:

    	os_result_t result;
    	os_descriptor_t	s;
    
    	result = os_socket_create(AF_INET, SOCK_STREAM, 0, &s);
    	if (result != OS_R_SUCCESS) {
    		/* Do something about the error. */
    		return;
    	}

Not so good:

    	int s;
    
    	/*
    	 * Obviously using interfaces like socket() (below) is allowed
    	 * since otherwise you couldn't call operating system routines; the
    	 * point is not to write more interfaces like them.
    	 */
    	s = socket(AF_INET, SOCK_STREAM, 0);
    	if (s < 0) {
    		/* Do something about the error using errno. */
    		return;
    	}

#### Integral Types

Careful thought should be given to whether an integral type should be signed or
unsigned, and to whether a specific size is required.  The basic rule of thumb
is to use `size_t` for sizes, cardinalities or ordinal numbers (e.g. iteration
counters, array subscripts).  Use unsigned type for small quantities that can’t
be negative, use signed types for small quantities that bear a sign, and finally
use ptrdiff_t for large differences that bear a sign.  Assignments and
comparisons between signed and unsigned integers should be avoided; suppressing
the warnings with casts is not desirable.

C99 standard integer types are generally preferred, and must be used when
`unsigned long` or `short` could be ambiguous, and `size_t` is preferred to
`unsigned int` variables.

#### Clear Success or Failure

A function should report success or failure, and do so accurately.  It
should never fail silently.  Use of [design by contract](dev.md#dbc)
can help here.

When a function is designed to return results to the caller by assigning
to caller variables through pointer arguments, it should perform the
assignment only if it succeeds, and leave the variables unmodified if it
fails.  A `REQUIRE()` statement should be used to ensure that the pointer
is in a sane state when the function is called.

The `isc_result_t` is provided for use by result codes.  See the
[results](dev.md#results) section of the [developer
information](dev.md) page for more details.

#### Testing Bits

Bit testing should be as follows:

Good:

    	/* Test if flag set. */
    	if ((flags & FOO) != 0) {
    
    	}
    	/* Test if flag clear. */
    	if ((flags & BAR) == 0) {
    
    	}
    	/* Test if both flags set. */
    	if ((flags & (FOO|BAR)) == (FOO|BAR)) {
    
    	}

Bad:

    	/* Test if flag set. */
    	if (flags & FOO) {
    
    	}
    	/* Test if flag clear. */
    	if (! (flags & BAR)) {
    
    	}

#### Testing for Zero or Non-zero

Explicit testing against zero is required for numeric, non-boolean
variables.

Good:

    	int i = 10;
    
    	/* ... */
    
    	if (i != 0) {
    		/* Do something. */
    	}

Bad:

    	int i = 10;
    
    	/* ... */
    
    	if (i) {
    		/* Do something. */
    	}

#### Null Pointer

The null pointer value should be referred to as `NULL`, not `0`.

Testing to see whether a pointer is `NULL` should be an explicit
comparison; do not treat a pointer variable as if it were a boolean.

Good:

    	char *c = NULL;
    
    	/* ... */
    
    	if (c != NULL) {
    		/* Do something. */
    	}

Bad:

    	char *c = NULL;
    
    	/* ... */
    
    	if (c) {
    		/* Do something. */
    	}

#### The Ternary Operator

The `?:` operator should mostly be avoided.  It is tolerated when deciding
what value to pass as a parameter to a function, such as frequently happens
with printf, and also when a simple (non-compound) value is being used in
assignment or as part of a calculation.

If a statement containing a ternary operator spills over more than one
line, put the `?` and `:` at the beginning of the following lines with two
additional spaces of indent.

Using the ternary operator to specify a return value is very rarely
permissible, and never when returning result codes.

Good:

    	printf("%c is%s a number.\\n", c, isdigit(c) ? "" : " NOT");
    	l = (l1 < l2) ? l1 : l2;
    	s = (a_very_long_variable < an_even_longer_variable)
    	      ? "true"
    	      : "false";
    	if (gp.length + (go < 16384 ? 2 : 3) >= name->length) {
    		/* whatever */
    	}

    Okay:

    	return ((length1 < length2) ? -1 : 1);

    Bad:

    	return (success ? ISC_R_SUCCESS : ISC_R_FAILURE);

#### Assignment in Parameters

Variables should not have their values assigned or changed when being
passed as parameters, except perhaps for the increment and decrement
operators.

Bad:

    	isc_mem_get(mctx, size = 20);

Okay:

    	fputc(c++, stdout);

#### Invalidating Pointers

When the data a pointer points to has been freed, or is otherwise no longer
valid, the pointer should be set to `NULL` unless the pointer is part of a
structure which is itself going to be freed immediately.

Good:

    	char *text;
    
    	/* text is initialized here. */
    
    	isc_mem_free(mctx, text);
    	text = NULL;

#### Variable Scopes

Always use minimal scopes for the variables, e.g. use block scope instead of
local scope whenever possible.

Bad:
    	void
    	foo() {
    		size_t i;
    		[...];
    		for (i = 0; i < 10; i++);
    		[...]
    	}

Good:
    	void
    	foo() {
    		[...];
    		for (size_t i = 0; i < 10; i++);
    		[...]
    	}

Bad:
    	void
    	foo() {
    		size_t j = 0;
    		[...] /* j not used here */
    		if (true) {
    			while (j < 10) ++j;
    		}
    		[...] /* j not used here */
    		return (0);
    	}

Good:
    	void
    	foo() {
    		[...]
    		if (true) {
    			size_t j = 0;
    			while (j < 10) ++j;
    		}
    		[...]
    	}

Integrating cppcheck with editor of your choice (f.e. flycheck with emacs) could
be a great help in identifying places where variable scopes can be reduced.

#### Initializing variables

Static initializers should be used instead of memset.

Good:
    	char array[10] = { 0 };

Bad:
    	char array[10];
    	memset(array, 0, sizeof(array));

Designated initializers should be used to initialize structures.

Good:
    	struct example {
    		int foo;
    		int bar;
    		int baz;
    	};
    
    	struct example x = { .foo = -1 };

Bad:
    	struct example {
    		int foo;
    		int bar;
    		int baz;
    	};
    
    	struct example x;
    
    	x.foo = -1;
    	x.bar = 0;
    	x.baz = 0;

Good:
    	struct example {
    		int foo;
    		int bar;
    		int baz;
    	};
    
    	struct example *x = isc_mem_get(mctx, sizeof(*x));
    
    	*x = (struct example){ .foo = -1 };

Bad:
    	struct example {
    		int foo;
    		int bar;
    		int baz;
    	};
    
    	struct example *x = isc_mem_get(mctx, sizeof(*x));
    
    	x->foo = -1;
    	x->bar = 0;
    	x->baz = 0;

#### Const

Declare variables as constant if they are not to be modified.

#### Variable-Length Arrays

Use VLAs where it is more appropriate to allocate the memory on the stack rather
than allocate it using `isc_mem_get()` from the heap.  Usually, a short lived
arrays local to that particular functions would be good fit for using VLAs.

#### <a name="public_namespace"></a>Public Interface Namespace

All public interfaces to functions, macros, typedefs, and variables
provided by the library, should use names of the form
`{library}_{module}_{what}`, such as:

    	isc_buffer_t			    /* typedef */
    	dns_name_setbuffer(name, buffer)	/* function */
    	ISC_LIST_HEAD(list)		     /* macro */
    	isc_commandline_argument		/* variable */

Structures which are `typedef`'d generally have the name of the typedef
sans the final `_t`:

    	typedef struct dns_rbtnode dns_rbtnode_t;
    	struct dns_rbtnode {
    		/* ... members ... */
    	}

In some cases, structures are specific to a single C file and are
opaque outside that file.  In these cases, the `typedef` occurs in the
associated header file, but the structure definition in the C file
itself.  Examples of this include the zone object `dns_zone_t`;
the structure is only accessible via get/set functions in
`lib/dns/zone.c`.  Other times, structure members can be accessed
from outside the C file where they are implemented; examples include
`dns_view_t`.  Which way to implement a particular object is up to
the developer's discretion.

Generally speaking, macros are defined with all capital letters, but this
is not universally consistent (eg, numerous `isc_buffer_{foo}` macros).

The `{module}` and `{what}` segments of the name do not have underscores
separating natural word elements, as demonstrated in
`isc_commandline_argument` and `dns_name_setbuffer` above.  The `{module}`
part is usually the same as the basename of the source file, but sometimes
other `{module}` interfaces appear within one file, such as `dns_label_*`
interfaces in `lib/dns/name.c`.  However, in the public libraries the file
name must be the same as some module interface provided by the file; e.g.,
`dns_rbt_*` interfaces would not be declared in a file named redblack.c (in
lieu of any other `dns_redblack_*` interfaces in the file).

The one notable exception to this naming rule is the interfaces provided by
`<isc/util.h>`.  There's a large caveat associated with the public
description of this file that it is hazardous to use because it pollutes
the general namespace.

When the signature of a public function needs to change, the old function
name should be retained for backward compatibility, if at all possible.
For example, when `dns_zone_setfile()` needed to include a file format
parameter, it was changed to `dns_zone_setfile2()`; the original function
name became a wrapper for the new function, calling it with the default
value of the format parameter:

    	isc_result_t
    	dns_zone_setfile(dns_zone_t *zone, const char *file) {
    		return (dns_zone_setfile2(zone, file, dns_masterformat_text);
    	}
    
    	isc_result_t
    	dns_zone_setfile2(dns_zone_t *zone, const char *file,
    			  dns_masterformat_t format)
    	{
    		...
    	}

#### <a name="private_namespace"></a>Shared Private Interfaces

When a module provides an interface for internal use by other modules in
the library or by unit tests, it should use the same naming convention
described for the public interfaces, except `{library}` and `{module}` are
separated by a double-underscore.  This indicates that the name is
internal, its API is not as formal as the public API, and thus it might
change without any sort of notice.  Examples of this usage include
`dns__zone_loadpending()` and `isc__taskmgr_ready()`.

In many cases, a public interface is instantiated by a private back-end
implementation.  The double-underscore naming style is sometimes used in
that situation; for example, `isc_task_attach()` calls the `attach`
function provided by a task API implementation; in BIND 9, this function
is provided by `isc__task_attach()`.

Other times, private interface implementations are static functions
that are pointed to by "method" tables.  For example, the `dns_db`
interface is implemented in several places, including `lib/dns/rbtdb.c`
(the red-black tree database used for internal storage of zones and
cache data) and `lib/dns/sdlz.c` (an interface to DLZ modules).
An object of type `dns_dbmethods_t` is created for each of these,
containing function pointers to the local implementations of each
of the `dns_db` API functions.  The `dns_db_findnode()` function
is provided by static functions called `findnode()` in each file,
and so on.

#### Initialization

When an object is allocated from the heap, all fields in the object must be
initialized.

#### Dead Code Pruning

Source which becomes obsolete should be removed, not just disabled with
`#if 0 ... #endif`.

#### Portability

When using a C library function, consider whether all operating systems
support it.  Is it in the POSIX standard?  If so, how long has it been
there? (BIND is still run on some operating systems released in the
1990s.)  Is its behavior the same on all platforms?  Is its signature
the same?  Are integer parameters the same size and signedness?  Does it
always return the same values on success, and set the same `errno` codes
on failure?

If there is a chance the library call may not be completely portable,
edit `configure.in` to check for it on the local system and only call
it from within a suitable `#ifdef`.  If the function is nonoptional,
it may be necessary to add your own implementation of it (or copy one
from a source with a BSD-compatible license).

BIND provides portable internal versions of many common library calls.
Some are designed to ensure that library calls have standardized
[ISC result codes](dev.md#results) instead of using potentially
nonwportable `errno` values; these include the file operations
in `isc_file` and `isc_stdio`.  Others, such as `isc_tm_strptime()`,
are needed to ensure consistent cross-platform behavior.
Others simply provide needed functions on platforms that don't
have them: for example, `isc_string_strlcpy()`  is an implementation
of the BSD-specific `strlcpy()` function.  On Linux and systems
without a `strlcpy()` function, it is `#define`d to `isc_string_strlcpy()`

In some cases, UNIX and Windows implementations of functions are kept
in separate files, such as `lib/isc/unix/file.c` and `lib/isc/win32/file.c`.

#### Some notes on standard functions

* Always use `memmove()` rather than `memcpy()`.
* If using `snprintf()` in a source file, be sure it includes `<isc/print.h>`

#### Log messages

Error and warning messages should be logged through the [logging
system](dev.md#logging).  Debugging `printf`s may be used during
development, but must be removed when the debugging is finished.

Log messages do not start with a capital letter, nor do they end in a
period, and they are not followed by newlines.

When variable text such as a file name or domain name occurs as part of a
log message, it should be enclosed in single quotes, as in "zone '%s' is
lame".

When the variable text forms a separate phrase, such as when it separated
from the rest of the message by a colon, it can be left unquoted:

   	isc_log_write(... "open: %s: %s", filename, isc_result_totext(result));

File names (`__FILE__`), line numbers (`__LINE__`), function names,
memory addresses, and other references to program internals may be used
in debugging messages and in messages to report programming errors detected
at runtime.  They may not be used in messages that indicate errors in the
program's inputs or operation.

### <a name="pystyle"></a>Python

BIND 9 contains some optional tools written in Python, in the `bin/python` subdirectory.  Python scripts are stored in the git repository as `{toolname}.py.in`; and `{toolname}.py` will be generated by `configure` (which determines, among other things, the path to the Python interpreter).

For Python coding, we abide by the Python style guidelines described [here](http://www.python.org/dev/peps/pep-0008/), with a few modifications:

* The `__init__()` method should always be the first one declared in a
  class definition, like so:

    	class Foo:
    	    # constructor definition here
    	    def __init__(self):
    		...
    	    # other functions may follow
    	    def bar(self):
    		...
    		Close all file and socket objects

* All Python standard library objects that have an underlying file
  descriptor (fd) should be closed explicitly using the `.close()` method.

* In cases where a file is opened and closed in a single block, it
  is often preferable to use the `with` statement:

    	with open('filename') as f:
    	    do_something_with(f)

### <a name="plstyle"></a>Perl

Perl is NOT required for building, installing, or using the BIND 9 name
server.  However, BIND 9 may use Perl for its system test environment, for
certain optional server add-on components, and in some cases for generating
source files (such as `bind9.xsl.h`, converted from `bind9.xsl`) which are
then committed to to the git repository.

Perl 5 is assumed; Perl scripts do not need to work in Perl 4.

Perl source code should follow the conventions for C source code where
applicable.

### <a name="shstyle"></a>Bourne Shell

Shell scripts must be as portable as possible and should therefore conform
strictly to POSIX standards.  Shell extensions such as those introduced in
Bash should be avoided.  Some pitfalls to avoid:

* To capture the output of a command, use `` `backquotes` `` rather than
  `$(parentheses)`
* For arithmetical computation, use `` `expr {expression}` ``, not
  `$((expression))`
* To test string length use `` `expr $string : ".*"` `` rather than ``
  `expr length $string` ``
* To test for the presence of a string in a file without printing anything
  to stdout, use `"grep string filename > /dev/null 2>&1"`, rather than
  `"grep -q string filename"`.
* To test for file existence use `"test -f"` rather than `"test -e"`
* Don't use newline (`\\n`) when calling `echo`. Either use another `echo`
  statement, or use `"cat << EOF"`.
* To set a variable from outside awk, use `"awk '{...}' var=value"` rather
  than `"awk -vvar=value '{...}'"`
* Don't close stdout/stderr descriptors (`>&-`), but redirect them to /dev/null
  instead (`>/dev/null`) as the closed descriptor might get reused leading to
  unpredictable behaviour when using `fprintf(stderr, ...)`
