.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

..
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.

   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

.. Reference:

BIND 9 Configuration Reference
==============================

BIND 9 configuration is broadly similar to BIND 8; however, there are a
few new areas of configuration, such as views. BIND 8 configuration
files should work with few alterations in BIND 9, although more complex
configurations should be reviewed to check if they can be more
efficiently implemented using the new features found in BIND 9.

BIND 4 configuration files can be converted to the new format using the
shell script ``contrib/named-bootconf/named-bootconf.sh``.

.. _configuration_file_elements:

Configuration File Elements
---------------------------

Following is a list of elements used throughout the BIND configuration
file documentation:

.. glossary::

    ``acl_name``
        The name of an ``address_match_list`` as defined by the ``acl`` statement.

    ``address_match_list``
        A list of one or more ``ip_addr``, ``ip_prefix``, ``key_id``, or ``acl_name`` elements, see :ref:`address_match_lists`.

    ``masters_list``
        A named list of one or more ``ip_addr`` with optional ``key_id`` and/or ``ip_port``. A ``masters_list`` may include other ``masters_lists``.

    ``domain_name``
        A quoted string which will be used as a DNS name, for example "``my.test.domain``".

    ``namelist``
        A list of one or more ``domain_name`` elements.

    ``dotted_decimal``
        One to four integers valued 0 through 255 separated by dots ('.'), such as ``123``, ``45.67`` or ``89.123.45.67``.

    ``ip4_addr``
        An IPv4 address with exactly four elements in ``dotted_decimal`` notation.

    ``ip6_addr``
        An IPv6 address, such as ``2001:db8::1234` IPv6 scoped addresses that have ambiguity on their scope zones must be disambiguated by an appropriate zone ID with the percent character ('%') as delimiter. It is strongly recommended to use string zone names rather than numeric identifiers, in order to be robust against system configuration changes.  However, since there is no standard mapping for such names and identifier values, currently only interface names as link identifiers are supported, assuming one-to-one mapping between interfaces and links. For example, a link-local address ``fe80::1`` on the link attached to the interface ``ne0`` can be specified as ``fe80::1%ne0``. Note that on most systems link-local addresses always have the ambiguity, and need to be disambiguated.

    ``ip_addr``
        An ``ip4_addr`` or ``ip6_addr``.

    ``ip_dscp``
        A ``number`` between 0 and 63, used to select a differentiated services code point (DSCP) value for use with outgoing traffic on operating systems that support DSCP.

    ``ip_port``
        An IP port ``number``. The ``number`` is limited to 0 through 65535, with values below 1024 typically restricted to use by processes running as root. In some cases, an asterisk (``*``) character can be used as a placeholder to select a random high-numbered port.

    ``ip_prefix``
        An IP network specified as an ``ip_addr``, followed by a slash ('/') and then the number of bits in the netmask. Trailing zeros in an``ip_addr`` may omitted. For example, ``127/8`` is the network ``127.0.0.0`` with network ``1.2.3.0`` with netmask ``255.255.255.240``.
        When specifying a prefix involving a IPv6 scoped address the scope may be omitted. In that case the prefix will match packets from any scope.

    ``key_id``
        A ``domain_name`` representing the name of a shared key, to be used for transaction security.

    ``key_list``
        A list of one or more ``key_id``\ s, separated by semicolons and ending with a semicolon.

    ``number``
        A non-negative 32-bit integer (i.e., a number between 0 and 4294967295, inclusive). Its acceptable value might be further limited by the context in which it is used.

    ``fixedpoint``
        A non-negative real number that can be specified to the nearest one hundredth. Up to five digits can be specified before a decimal point, and up to two digits after, so the maximum value is 99999.99. Acceptable values might be further limited by the context in which it is used.

    ``path_name``
        A quoted string which will be used as a pathname, such as ``zones/master/my.test.domain``.

    ``port_list``
        A list of an ``ip_port`` or a port range. A port range is specified in the form of ``range`` followed by two ``ip_port``\ s, ``port_low`` and ``port_high``, which represents port numbers from ``port_low`` through ``port_high``, inclusive. ``port_low`` must not be larger than ``port_high``. For example, ``range 1024 65535`` represents ports from 1024 through 65535. In either case an asterisk ('\*') character is not allowed as a valid ``ip_port``.

    ``size_spec``
        A 64-bit unsigned integer, or the keywords ``unlimited`` or ``default``. Integers may take values 0 <= value <= 18446744073709551615, though certain parameters (such as ``max-journal-size``) may use a more limited range within these extremes. In most cases, setting a value to 0 does not literally mean zero; it means "undefined" or "as big as possible", depending on the context. See the explanations of particular parameters that use ``size_spec`` for details on how they interpret its use. Numeric values can optionally be followed by a scaling factor: ``K`` or ``k`` for kilobytes, ``M`` or ``m`` for megabytes, and ``G`` or ``g`` for gigabytes, which scale by 1024, 1024*1024, and 1024*1024*1024 respectively.
        ``unlimited`` generally means "as big as possible", and is usually the best way to safely set a very large number.
        ``default`` uses the limit that was in force when the server was started.

    ``size_or_percent``
            ``size_spec`` or integer value followed by'%' to represent percents. The behavior is exactly the same as ``size_spec``, but ``size_or_percent`` allows also to specify a positive integer value followed by '%' sign to represent percents.

    ``yes_or_no``
        Either ``yes`` or ``no``. The words ``true`` numbers ``1`` and ``0``. The words ``true`` and ``false`` are also accepted, as are the numbers ``1`` and ``0``.

    ``dialup_option``
        One of ``yes``, ``no``, ``notify``, ``notify-passive``, ``refresh`` or  ``passive``. When used in a zone, ``notify-passive``, ``refresh``, and ``passive`` are restricted to slave and stub zones.

.. _address_match_lists:

Address Match Lists
~~~~~~~~~~~~~~~~~~~

Syntax
^^^^^^

::

   address_match_list = address_match_list_element ; ...

   address_match_list_element = [ ! ] ( ip_address | ip_prefix |
        key key_id | acl_name | { address_match_list } )

Definition and Usage
^^^^^^^^^^^^^^^^^^^^

Address match lists are primarily used to determine access control for
various server operations. They are also used in the ``listen-on`` and
``sortlist`` statements. The elements which constitute an address match
list can be any of the following:

-  an IP address (IPv4 or IPv6)

-  an IP prefix (in '/' notation)

-  a key ID, as defined by the ``key`` statement

-  the name of an address match list defined with the ``acl`` statement

-  a nested address match list enclosed in braces

Elements can be negated with a leading exclamation mark (``!``), and the
match list names "any", "none", "localhost", and "localnets" are
predefined. More information on those names can be found in the
description of the acl statement.

The addition of the key clause made the name of this syntactic element
something of a misnomer, since security keys can be used to validate
access without regard to a host or network address. Nonetheless, the
term "address match list" is still used throughout the documentation.

When a given IP address or prefix is compared to an address match list,
the comparison takes place in approximately O(1) time. However, key
comparisons require that the list of keys be traversed until a matching
key is found, and therefore may be somewhat slower.

The interpretation of a match depends on whether the list is being used
for access control, defining ``listen-on`` ports, or in a ``sortlist``,
and whether the element was negated.

When used as an access control list, a non-negated match allows access
and a negated match denies access. If there is no match, access is
denied. The clauses ``allow-notify``, ``allow-recursion``,
``allow-recursion-on``, ``allow-query``, ``allow-query-on``,
``allow-query-cache``, ``allow-query-cache-on``, ``allow-transfer``,
``allow-update``, ``allow-update-forwarding``, ``blackhole``, and
``keep-response-order`` all use address match lists. Similarly, the
``listen-on`` option will cause the server to refuse queries on any of
the machine's addresses which do not match the list.

Order of insertion is significant. If more than one element in an ACL is
found to match a given IP address or prefix, preference will be given to
the one that came *first* in the ACL definition. Because of this
first-match behavior, an element that defines a subset of another
element in the list should come before the broader element, regardless
of whether either is negated. For example, in ``1.2.3/24; ! 1.2.3.13;``
the 1.2.3.13 element is completely useless because the algorithm will
match any lookup for 1.2.3.13 to the 1.2.3/24 element. Using
``! 1.2.3.13; 1.2.3/24`` fixes that problem by having 1.2.3.13 blocked
by the negation, but all other 1.2.3.\* hosts fall through.

.. _comment_syntax:

Comment Syntax
~~~~~~~~~~~~~~

The BIND 9 comment syntax allows for comments to appear anywhere that
whitespace may appear in a BIND configuration file. To appeal to
programmers of all kinds, they can be written in the C, C++, or
shell/perl style.

Syntax
^^^^^^

::

   /* This is a BIND comment as in C */

::

   // This is a BIND comment as in C++

::

   # This is a BIND comment as in common UNIX shells
   # and perl

Definition and Usage
^^^^^^^^^^^^^^^^^^^^

Comments may appear anywhere that whitespace may appear in a BIND
configuration file.

C-style comments start with the two characters /\* (slash, star) and end
with \*/ (star, slash). Because they are completely delimited with these
characters, they can be used to comment only a portion of a line or to
span multiple lines.

C-style comments cannot be nested. For example, the following is not
valid because the entire comment ends with the first \*/:

::

   /* This is the start of a comment.
      This is still part of the comment.
   /* This is an incorrect attempt at nesting a comment. */
      This is no longer in any comment. */

C++-style comments start with the two characters // (slash, slash) and
continue to the end of the physical line. They cannot be continued
across multiple physical lines; to have one logical comment span
multiple lines, each line must use the // pair. For example:

::

   // This is the start of a comment.  The next line
   // is a new comment, even though it is logically
   // part of the previous comment.

Shell-style (or perl-style, if you prefer) comments start with the
character ``#`` (number sign) and continue to the end of the physical
line, as in C++ comments. For example:

::

   # This is the start of a comment.  The next line
   # is a new comment, even though it is logically
   # part of the previous comment.

..

.. warning::

   You cannot use the semicolon (``;``) character to start a comment such
   as you would in a zone file. The semicolon indicates the end of a
   configuration statement.

.. _Configuration_File_Grammar:

Configuration File Grammar
--------------------------

A BIND 9 configuration consists of statements and comments. Statements
end with a semicolon. Statements and comments are the only elements that
can appear without enclosing braces. Many statements contain a block of
sub-statements, which are also terminated with a semicolon.

The following statements are supported:

    ``acl``
        defines a named IP address matching list, for access control and other uses.

    ``controls``
        declares control channels to be used by the ``rndc`` utility.

    ``dnssec-policy``
        describes a DNSSEC key and signing policy for zones. See :ref:`dnssec-policy Grammar <dnssec_policy_grammar>` for details.

    ``include``
        includes a file.

    ``key``
        specifies key information for use in authentication and authorization using TSIG.

    ``logging``
        specifies what the server logs, and where the log messages are sent.

    ``masters``
        defines a named masters list for inclusion in stub and slave zones' ``masters`` or ``also-notify`` lists.

    ``options``
        controls global server configuration options and sets defaults for other statements.

    ``server``
        sets certain configuration options on a per-server basis.

    ``statistics-channels``
        declares communication channels to get access to ``named`` statistics.

    ``trust-anchors``
        defines DNSSEC trust anchors: if used with the ``initial-key`` or ``initial-ds`` keyword, trust anchors are kept up to date using :rfc:`5011` trust anchor maintenance, and if used with ``static-key`` or ``static-ds``, keys are permanent.

    ``managed-keys``
        is identical to ``trust-anchors``; this option is deprecated in favor of ``trust-anchors`` with the ``initial-key`` keyword, and may be removed in a future release. for backward compatibility.

    ``trusted-keys``
        defines permanent trusted DNSSEC keys; this option is deprecated in favor of ``trust-anchors`` with the ``static-key`` keyword, and may be removed in a future release.                                  |
    ``view``
        defines a view.

    ``zone``
        defines a zone.

The ``logging`` and ``options`` statements may only occur once per
configuration.

.. _acl_grammar:

``acl`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/acl.grammar.rst

.. _acl:

``acl`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``acl`` statement assigns a symbolic name to an address match list.
It gets its name from a primary use of address match lists: Access
Control Lists (ACLs).

The following ACLs are built-in:

    ``any``
        Matches all hosts.

    ``none``
        Matches no hosts.

    ``localhost``
        Matches the IPv4 and IPv6 addresses of all network interfaces on the system. When addresses are added or removed, the ``localhost`` ACL element is updated to reflect the changes.

    ``localnets``
        Matches any host on an IPv4 or IPv6 network for which the system has an interface. When addresses are added or removed, the ``localnets`` ACL element is updated to reflect the changes. Some systems do not provide a way to determine the prefix lengths of local IPv6  addresses. In such a case, ``localnets`` only matches the local IPv6 addresses, just like ``localhost``.

.. _controls_grammar:

``controls`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/controls.grammar.rst

.. _controls_statement_definition_and_usage:

``controls`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``controls`` statement declares control channels to be used by
system administrators to control the operation of the name server. These
control channels are used by the ``rndc`` utility to send commands to
and retrieve non-DNS results from a name server.

An ``inet`` control channel is a TCP socket listening at the specified
``ip_port`` on the specified ``ip_addr``, which can be an IPv4 or IPv6
address. An ``ip_addr`` of ``*`` (asterisk) is interpreted as the IPv4
wildcard address; connections will be accepted on any of the system's
IPv4 addresses. To listen on the IPv6 wildcard address, use an
``ip_addr`` of ``::``. If you will only use ``rndc`` on the local host,
using the loopback address (``127.0.0.1`` or ``::1``) is recommended for
maximum security.

If no port is specified, port 953 is used. The asterisk "``*``" cannot
be used for ``ip_port``.

The ability to issue commands over the control channel is restricted by
the ``allow`` and ``keys`` clauses. Connections to the control channel
are permitted based on the ``address_match_list``. This is for simple IP
address based filtering only; any ``key_id`` elements of the
``address_match_list`` are ignored.

A ``unix`` control channel is a UNIX domain socket listening at the
specified path in the file system. Access to the socket is specified by
the ``perm``, ``owner`` and ``group`` clauses. Note on some platforms
(SunOS and Solaris) the permissions (``perm``) are applied to the parent
directory as the permissions on the socket itself are ignored.

The primary authorization mechanism of the command channel is the
``key_list``, which contains a list of ``key_id``\ s. Each ``key_id`` in
the ``key_list`` is authorized to execute commands over the control
channel. See :ref:`admin_tools`) for information about
configuring keys in ``rndc``.

If the ``read-only`` clause is enabled, the control channel is limited
to the following set of read-only commands: ``nta -dump``, ``null``,
``status``, ``showzone``, ``testgen``, and ``zonestatus``. By default,
``read-only`` is not enabled and the control channel allows read-write
access.

If no ``controls`` statement is present, ``named`` will set up a default
control channel listening on the loopback address 127.0.0.1 and its IPv6
counterpart ::1. In this case, and also when the ``controls`` statement
is present but does not have a ``keys`` clause, ``named`` will attempt
to load the command channel key from the file ``rndc.key`` in ``/etc``
(or whatever ``sysconfdir`` was specified as when BIND was built). To
create a ``rndc.key`` file, run ``rndc-confgen -a``.

The ``rndc.key`` feature was created to ease the transition of systems
from BIND 8, which did not have digital signatures on its command
channel messages and thus did not have a ``keys`` clause. It makes it
possible to use an existing BIND 8 configuration file in BIND 9
unchanged, and still have ``rndc`` work the same way ``ndc`` worked in
BIND 8, simply by executing the command ``rndc-confgen -a`` after BIND 9
is installed.

Since the ``rndc.key`` feature is only intended to allow the
backward-compatible usage of BIND 8 configuration files, this feature
does not have a high degree of configurability. You cannot easily change
the key name or the size of the secret, so you should make a
``rndc.conf`` with your own key if you wish to change those things. The
``rndc.key`` file also has its permissions set such that only the owner
of the file (the user that ``named`` is running as) can access it. If
you desire greater flexibility in allowing other users to access
``rndc`` commands, then you need to create a ``rndc.conf`` file and make
it group readable by a group that contains the users who should have
access.

To disable the command channel, use an empty ``controls`` statement:
``controls { };``.

.. _include_grammar:

``include`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   include filename;

.. _include_statement:

``include`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``include`` statement inserts the specified file (or files if a valid glob
expression is detected) at the point where the ``include`` statement is
encountered. The ``include`` statement facilitates the administration of
configuration files by permitting the reading or writing of some things but not
others. For example, the statement could include private keys that are readable
only by the name server.

.. _key_grammar:

``key`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/key.grammar.rst

.. _key_statement:

``key`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``key`` statement defines a shared secret key for use with TSIG (see
:ref:`tsig`) or the command channel (see :ref:`controls_statement_definition_and_usage`).

The ``key`` statement can occur at the top level of the configuration
file or inside a ``view`` statement. Keys defined in top-level ``key``
statements can be used in all views. Keys intended for use in a
``controls`` statement (see :ref:`controls_statement_definition_and_usage`)
must be defined at the top level.

The key_id, also known as the key name, is a domain name uniquely
identifying the key. It can be used in a ``server`` statement to cause
requests sent to that server to be signed with this key, or in address
match lists to verify that incoming requests have been signed with a key
matching this name, algorithm, and secret.

The algorithm_id is a string that specifies a security/authentication
algorithm. The ``named`` server supports ``hmac-md5``, ``hmac-sha1``,
``hmac-sha224``, ``hmac-sha256``, ``hmac-sha384`` and ``hmac-sha512``
TSIG authentication. Truncated hashes are supported by appending the
minimum number of required bits preceded by a dash, e.g.
``hmac-sha1-80``. The secret_string is the secret to be used by the
algorithm, and is treated as a Base64 encoded string.

.. _logging_grammar:

``logging`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/logging.grammar.rst

.. _logging_statement:

``logging`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``logging`` statement configures a wide variety of logging options
for the name server. Its ``channel`` phrase associates output methods,
format options and severity levels with a name that can then be used
with the ``category`` phrase to select how various classes of messages
are logged.

Only one ``logging`` statement is used to define as many channels and
categories as are wanted. If there is no ``logging`` statement, the
logging configuration will be:

::

   logging {
        category default { default_syslog; default_debug; };
        category unmatched { null; };
   };

If ``named`` is started with the ``-L`` option, it logs to the specified
file at startup, instead of using syslog. In this case the logging
configuration will be:

::

   logging {
        category default { default_logfile; default_debug; };
        category unmatched { null; };
   };

The logging configuration is only established when the entire
configuration file has been parsed. When the server is starting up, all
logging messages regarding syntax errors in the configuration file go to
the default channels, or to standard error if the ``-g`` option was
specified.

.. _channel:

The ``channel`` Phrase
^^^^^^^^^^^^^^^^^^^^^^

All log output goes to one or more *channels*; you can make as many of
them as you want.

Every channel definition must include a destination clause that says
whether messages selected for the channel go to a file, to a particular
syslog facility, to the standard error stream, or are discarded. It can
optionally also limit the message severity level that will be accepted
by the channel (the default is ``info``), and whether to include a
``named``-generated time stamp, the category name and/or severity level
(the default is not to include any).

The ``null`` destination clause causes all messages sent to the channel
to be discarded; in that case, other options for the channel are
meaningless.

The ``file`` destination clause directs the channel to a disk file. It
can include additional arguments to specify how large the file is
allowed to become before it is rolled to a backup file (``size``), how
many backup versions of the file will be saved each time this happens
(``versions``), and the format to use for naming backup versions
(``suffix``).

The ``size`` option is used to limit log file growth. If the file ever
exceeds the specified size, then ``named`` will stop writing to the file
unless it has a ``versions`` option associated with it. If backup
versions are kept, the files are rolled as described below. If there is
no ``versions`` option, no more data will be written to the log until
some out-of-band mechanism removes or truncates the log to less than the
maximum size. The default behavior is not to limit the size of the file.

File rolling only occurs when the file exceeds the size specified with
the ``size`` option. No backup versions are kept by default; any
existing log file is simply appended. The ``versions`` option specifies
how many backup versions of the file should be kept. If set to
``unlimited``, there is no limit.

The ``suffix`` option can be set to either ``increment`` or
``timestamp``. If set to ``timestamp``, then when a log file is rolled,
it is saved with the current timestamp as a file suffix. If set to
``increment``, then backup files are saved with incrementing numbers as
suffixes; older files are renamed when rolling. For example, if
``versions`` is set to 3 and ``suffix`` to ``increment``, then when
``filename.log`` reaches the size specified by ``size``,
``filename.log.1`` is renamed to ``filename.log.2``, ``filename.log.0``
is renamed to ``filename.log.1``, and ``filename.log`` is renamed to
``filename.log.0``, whereupon a new ``filename.log`` is opened.

Example usage of the ``size``, ``versions``, and ``suffix`` options:

::

   channel an_example_channel {
       file "example.log" versions 3 size 20m suffix increment;
       print-time yes;
       print-category yes;
   };

The ``syslog`` destination clause directs the channel to the system log.
Its argument is a syslog facility as described in the ``syslog`` man
page. Known facilities are ``kern``, ``user``, ``mail``, ``daemon``,
``auth``, ``syslog``, ``lpr``, ``news``, ``uucp``, ``cron``,
``authpriv``, ``ftp``, ``local0``, ``local1``, ``local2``, ``local3``,
``local4``, ``local5``, ``local6`` and ``local7``, however not all
facilities are supported on all operating systems. How ``syslog`` will
handle messages sent to this facility is described in the
``syslog.conf`` man page. If you have a system which uses a very old
version of ``syslog`` that only uses two arguments to the ``openlog()``
function, then this clause is silently ignored.

On Windows machines syslog messages are directed to the EventViewer.

The ``severity`` clause works like ``syslog``'s "priorities", except
that they can also be used if you are writing straight to a file rather
than using ``syslog``. Messages which are not at least of the severity
level given will not be selected for the channel; messages of higher
severity levels will be accepted.

If you are using ``syslog``, then the ``syslog.conf`` priorities will
also determine what eventually passes through. For example, defining a
channel facility and severity as ``daemon`` and ``debug`` but only
logging ``daemon.warning`` via ``syslog.conf`` will cause messages of
severity ``info`` and ``notice`` to be dropped. If the situation were
reversed, with ``named`` writing messages of only ``warning`` or higher,
then ``syslogd`` would print all messages it received from the channel.

The ``stderr`` destination clause directs the channel to the server's
standard error stream. This is intended for use when the server is
running as a foreground process, for example when debugging a
configuration.

The server can supply extensive debugging information when it is in
debugging mode. If the server's global debug level is greater than zero,
then debugging mode will be active. The global debug level is set either
by starting the ``named`` server with the ``-d`` flag followed by a
positive integer, or by running ``rndc trace``. The global debug level
can be set to zero, and debugging mode turned off, by running ``rndc
notrace``. All debugging messages in the server have a debug level, and
higher debug levels give more detailed output. Channels that specify a
specific debug severity, for example:

::

   channel specific_debug_level {
       file "foo";
       severity debug 3;
   };

will get debugging output of level 3 or less any time the server is in
debugging mode, regardless of the global debugging level. Channels with
``dynamic`` severity use the server's global debug level to determine
what messages to print.

``print-time`` can be set to ``yes``, ``no``, or a time format
specifier, which may be one of ``local``, ``iso8601`` or
``iso8601-utc``. If set to ``no``, then the date and time will not be
logged. If set to ``yes`` or ``local``, the date and time are logged in
a human readable format, using the local time zone. If set to
``iso8601`` the local time is logged in ISO8601 format. If set to
``iso8601-utc``, then the date and time are logged in ISO8601 format,
with time zone set to UTC. The default is ``no``.

``print-time`` may be specified for a ``syslog`` channel, but it is
usually pointless since ``syslog`` also logs the date and time.

If ``print-category`` is requested, then the category of the message
will be logged as well. Finally, if ``print-severity`` is on, then the
severity level of the message will be logged. The ``print-`` options may
be used in any combination, and will always be printed in the following
order: time, category, severity. Here is an example where all three
``print-`` options are on:

``28-Feb-2000 15:05:32.863 general: notice: running``

If ``buffered`` has been turned on the output to files will not be
flushed after each log entry. By default all log messages are flushed.

There are four predefined channels that are used for ``named``'s default
logging as follows. If ``named`` is started with the ``-L`` then a fifth
channel ``default_logfile`` is added. How they are used is described in
:ref:`the_category_phrase`.

::

   channel default_syslog {
       // send to syslog's daemon facility
       syslog daemon;
       // only send priority info and higher
       severity info;
   };

   channel default_debug {
       // write to named.run in the working directory
       // Note: stderr is used instead of "named.run" if
       // the server is started with the '-g' option.
       file "named.run";
       // log at the server's current debug level
       severity dynamic;
   };

   channel default_stderr {
       // writes to stderr
       stderr;
       // only send priority info and higher
       severity info;
   };

   channel null {
      // toss anything sent to this channel
      null;
   };

   channel default_logfile {
       // this channel is only present if named is
       // started with the -L option, whose argument
       // provides the file name
       file "...";
       // log at the server's current debug level
       severity dynamic;
   };

The ``default_debug`` channel has the special property that it only
produces output when the server's debug level is nonzero. It normally
writes to a file called ``named.run`` in the server's working directory.

For security reasons, when the ``-u`` command line option is used, the
``named.run`` file is created only after ``named`` has changed to the
new UID, and any debug output generated while ``named`` is starting up
and still running as root is discarded. If you need to capture this
output, you must run the server with the ``-L`` option to specify a
default logfile, or the ``-g`` option to log to standard error which you
can redirect to a file.

Once a channel is defined, it cannot be redefined. Thus you cannot alter
the built-in channels directly, but you can modify the default logging
by pointing categories at channels you have defined.

.. _the_category_phrase:

The ``category`` Phrase
^^^^^^^^^^^^^^^^^^^^^^^

There are many categories, so you can send the logs you want to see
wherever you want, without seeing logs you don't want. If you don't
specify a list of channels for a category, then log messages in that
category will be sent to the ``default`` category instead. If you don't
specify a default category, the following "default default" is used:

::

   category default { default_syslog; default_debug; };

If you start ``named`` with the ``-L`` option then the default category
is:

::

   category default { default_logfile; default_debug; };

As an example, let's say you want to log security events to a file, but
you also want keep the default logging behavior. You'd specify the
following:

::

   channel my_security_channel {
       file "my_security_file";
       severity info;
   };
   category security {
       my_security_channel;
       default_syslog;
       default_debug;
   };

To discard all messages in a category, specify the ``null`` channel:

::

   category xfer-out { null; };
   category notify { null; };

Following are the available categories and brief descriptions of the
types of log information they contain. More categories may be added in
future BIND releases.

.. include:: logging-categories.rst

.. _query_errors:

The ``query-errors`` Category
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``query-errors`` category is used to indicate why and how specific queries
resulted in responses which indicate an error.  Normally, these messages will be
logged at ``debug`` logging levels; note, however, that if query logging is
active, some will be logged at ``info``. The logging levels are described below:

At ``debug`` levels of 1 or higher, - or at ``info``, when query logging is
active - each response with the rcode of SERVFAIL is logged as follows:

``client 127.0.0.1#61502: query failed (SERVFAIL) for www.example.com/IN/AAAA at query.c:3880``

This means an error resulting in SERVFAIL was detected at line 3880 of source
file ``query.c``.  Log messages of this level will particularly help identify
the cause of SERVFAIL for an authoritative server.

At ``debug`` level 2 or higher, detailed context information about recursive
resolutions that resulted in SERVFAIL will be logged.  The log message will look
like this:

::

   fetch completed at resolver.c:2970 for www.example.com/A
   in 10.000183: timed out/success [domain:example.com,
   referral:2,restart:7,qrysent:8,timeout:5,lame:0,quota:0,neterr:0,
   badresp:1,adberr:0,findfail:0,valfail:0]

The first part before the colon shows that a recursive resolution for
AAAA records of www.example.com completed in 10.000183 seconds and the
final result that led to the SERVFAIL was determined at line 2970 of
source file ``resolver.c``.

The following part shows the detected final result and the latest result of
DNSSEC validation.  The latter is always "success" when no validation attempt
was made.  In this example, this query probably resulted in SERVFAIL because all
name servers are down or unreachable, leading to a timeout in 10 seconds.
DNSSEC validation was probably not attempted.

The last part, enclosed in square brackets, shows statistics collected for this
particular resolution attempt.  The ``domain`` field shows the deepest zone that
the resolver reached; it is the zone where the error was finally detected.  The
meaning of the other fields is summarized in the following list.

``referral``
    The number of referrals the resolver received throughout the resolution process. In the above example.com there are two.

``restart``
    The number of cycles that the resolver tried remote servers at the ``domain`` zone. In each cycle the resolver sends one query (possibly resending it, depending on the response) to each known name server of the ``domain`` zone.

``qrysent``
      The number of queries the resolver sent at the ``domain`` zone.

``timeout``
    The number of timeouts since the resolver received since the last response.

``lame``
    The number of lame servers the resolver detected at the ``domain`` zone. A server is detected to be lame either by an invalid response or as a result of lookup in BIND9's address database (ADB), where lame servers are cached.

``quota``
    The number of times the resolver was unable to send a query because it had exceeded the permissible fetch quota for a server.

``neterr``
    The number of erroneous results that the resolver encountered in sending queries at the ``domain`` zone. One common case is the remote server is unreachable and the resolver receives an ICMP unreachable error message.                         |

``badresp``
    The number of unexpected responses (other than``lame``) to queries sent by the resolver at the``domain`` zone.

``adberr``
    Failures in finding remote server addresses of the``domain`` zone in the ADB. One common case of this is that the remote server's name does not have any address records.

``findfail``
    Failures of resolving remote server addresses. This is a total number of failures throughout the eesolution process.

``valfail``
    Failures of DNSSEC validation. Validation failures are counted throughout the resolution process (not limited to the ``domain`` zone), but should only happen in ``domain``.

At ``debug`` level 3 or higher, the same messages as those at
``debug`` level 1 will be logged for other errors than
SERVFAIL. Note that negative responses such as NXDOMAIN are not errors, and are
not logged at this debug level.

At ``debug`` level 4 or higher, the detailed context information logged at
``debug`` level 2 will be logged for other errors than SERVFAIL and for negative
resonses such as NXDOMAIN.

.. _masters_grammar:

``masters`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/masters.grammar.rst

.. _masters_statement:

``masters`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``masters`` lists allow for a common set of masters to be easily used by
multiple stub and slave zones in their ``masters`` or ``also-notify``
lists.

.. _options_grammar:

``options`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is the grammar of the ``options`` statement in the ``named.conf``
file:

.. include:: ../misc/options.grammar.rst

.. _options:

``options`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``options`` statement sets up global options to be used by BIND.
This statement may appear only once in a configuration file. If there is
no ``options`` statement, an options block with each option set to its
default will be used.

``attach-cache``
   Allows multiple views to share a single cache database. Each view has
   its own cache database by default, but if multiple views have the
   same operational policy for name resolution and caching, those views
   can share a single cache to save memory and possibly improve
   resolution efficiency by using this option.

   The ``attach-cache`` option may also be specified in ``view``
   statements, in which case it overrides the global ``attach-cache``
   option.

   The cache_name specifies the cache to be shared. When the ``named``
   server configures views which are supposed to share a cache, it
   creates a cache with the specified name for the first view of these
   sharing views. The rest of the views will simply refer to the already
   created cache.

   One common configuration to share a cache would be to allow all views
   to share a single cache. This can be done by specifying the
   ``attach-cache`` as a global option with an arbitrary name.

   Another possible operation is to allow a subset of all views to share
   a cache while the others to retain their own caches. For example, if
   there are three views A, B, and C, and only A and B should share a
   cache, specify the ``attach-cache`` option as a view A (or B)'s
   option, referring to the other view name:

   ::

        view "A" {
          // this view has its own cache
          ...
        };
        view "B" {
          // this view refers to A's cache
          attach-cache "A";
        };
        view "C" {
          // this view has its own cache
          ...
        };

   Views that share a cache must have the same policy on configurable
   parameters that may affect caching. The current implementation
   requires the following configurable options be consistent among these
   views: ``check-names``, ``dnssec-accept-expired``,
   ``dnssec-validation``, ``max-cache-ttl``, ``max-ncache-ttl``,
   ``max-stale-ttl``, ``max-cache-size``, and ``min-cache-ttl``,
   ``min-ncache-ttl``, ``zero-no-soa-ttl``.

   Note that there may be other parameters that may cause confusion if
   they are inconsistent for different views that share a single cache.
   For example, if these views define different sets of forwarders that
   can return different answers for the same question, sharing the
   answer does not make sense or could even be harmful. It is
   administrator's responsibility to ensure configuration differences in
   different views do not cause disruption with a shared cache.

``directory``
   The working directory of the server. Any non-absolute pathnames in
   the configuration file will be taken as relative to this directory.
   The default location for most server output files (e.g.
   ``named.run``) is this directory. If a directory is not specified,
   the working directory defaults to \`\ ``.``', the directory from
   which the server was started. The directory specified should be an
   absolute path, and *must* be writable by the effective user ID of the
   ``named`` process.

``dnstap``
   ``dnstap`` is a fast, flexible method for capturing and logging DNS
   traffic. Developed by Robert Edmonds at Farsight Security, Inc., and
   supported by multiple DNS implementations, ``dnstap`` uses
   ``libfstrm`` (a lightweight high-speed framing library, see
   https://github.com/farsightsec/fstrm) to send event payloads which
   are encoded using Protocol Buffers (``libprotobuf-c``, a mechanism
   for serializing structured data developed by Google, Inc.; see
   https://developers.google.com/protocol-buffers/).

   To enable ``dnstap`` at compile time, the ``fstrm`` and
   ``protobuf-c`` libraries must be available, and BIND must be
   configured with ``--enable-dnstap``.

   The ``dnstap`` option is a bracketed list of message types to be
   logged. These may be set differently for each view. Supported types
   are ``client``, ``auth``, ``resolver``, ``forwarder``, and
   ``update``. Specifying type ``all`` will cause all ``dnstap``
   messages to be logged, regardless of type.

   Each type may take an additional argument to indicate whether to log
   ``query`` messages or ``response`` messages; if not specified, both
   queries and responses are logged.

   Example: To log all authoritative queries and responses, recursive
   client responses, and upstream queries sent by the resolver, use:

   ::

      dnstap {
        auth;
        client response;
        resolver query;
      };

   Logged ``dnstap`` messages can be parsed using the ``dnstap-read``
   utility (see :ref:`man_dnstap-read` for details).

   For more information on ``dnstap``, see http://dnstap.info.

   The fstrm library has a number of tunables that are exposed in
   ``named.conf``, and can be modified if necessary to improve
   performance or prevent loss of data. These are:

   -  ``fstrm-set-buffer-hint``: The threshold number of bytes to
      accumulate in the output buffer before forcing a buffer flush. The
      minimum is 1024, the maximum is 65536, and the default is 8192.

   -  ``fstrm-set-flush-timeout``: The number of seconds to allow
      unflushed data to remain in the output buffer. The minimum is 1
      second, the maximum is 600 seconds (10 minutes), and the default
      is 1 second.

   -  ``fstrm-set-output-notify-threshold``: The number of outstanding
      queue entries to allow on an input queue before waking the I/O
      thread. The minimum is 1 and the default is 32.

   -  ``fstrm-set-output-queue-model``: Controls the queuing semantics
      to use for queue objects. The default is ``mpsc`` (multiple
      producer, single consumer); the other option is ``spsc`` (single
      producer, single consumer).

   -  ``fstrm-set-input-queue-size``: The number of queue entries to
      allocate for each input queue. This value must be a power of 2.
      The minimum is 2, the maximum is 16384, and the default is 512.

   -  ``fstrm-set-output-queue-size``: The number of queue entries to
      allocate for each output queue. The minimum is 2, the maximum is
      system-dependent and based on ``IOV_MAX``, and the default is 64.

   -  ``fstrm-set-reopen-interval``: The number of seconds to wait
      between attempts to reopen a closed output stream. The minimum is
      1 second, the maximum is 600 seconds (10 minutes), and the default
      is 5 seconds. For convenience, TTL-style time unit suffixes may be
      used to specify the value.

   Note that all of the above minimum, maximum, and default values are
   set by the ``libfstrm`` library, and may be subject to change in
   future versions of the library. See the ``libfstrm`` documentation
   for more information.

``dnstap-output``
   Configures the path to which the ``dnstap`` frame stream will be sent
   if ``dnstap`` is enabled at compile time and active.

   The first argument is either ``file`` or ``unix``, indicating whether
   the destination is a file or a UNIX domain socket. The second
   argument is the path of the file or socket. (Note: when using a
   socket, ``dnstap`` messages will only be sent if another process such
   as ``fstrm_capture`` (provided with ``libfstrm``) is listening on the
   socket.)

   If the first argument is ``file``, then up to three additional
   options can be added: ``size`` indicates the size to which a
   ``dnstap`` log file can grow before being rolled to a new file;
   ``versions`` specifies the number of rolled log files to retain; and
   ``suffix`` indicates whether to retain rolled log files with an
   incrementing counter as the suffix (``increment``) or with the
   current timestamp (``timestamp``). These are similar to the ``size``,
   ``versions``, and ``suffix`` options in a ``logging`` channel. The
   default is to allow ``dnstap`` log files to grow to any size without
   rolling.

   ``dnstap-output`` can only be set globally in ``options``. Currently,
   it can only be set once while ``named`` is running; once set, it
   cannot be changed by ``rndc reload`` or ``rndc reconfig``.

``dnstap-identity``
   Specifies an ``identity`` string to send in ``dnstap`` messages. If
   set to ``hostname``, which is the default, the server's hostname will
   be sent. If set to ``none``, no identity string will be sent.

``dnstap-version``
   Specifies a ``version`` string to send in ``dnstap`` messages. The
   default is the version number of the BIND release. If set to
   ``none``, no version string will be sent.

``geoip-directory``
   When ``named`` is compiled using the MaxMind GeoIP2 geolocation API, this
   specifies the directory containing GeoIP database files.  By default, the
   option is set based on the prefix used to build the ``libmaxminddb`` module:
   for example, if the library is installed in ``/usr/local/lib``, then the
   default ``geoip-directory`` will be ``/usr/local/share/GeoIP``. On Windows,
   the default is the ``named`` working directory.  See :ref:`acl`
   for details about ``geoip`` ACLs.

``key-directory``
   When performing dynamic update of secure zones, the directory where
   the public and private DNSSEC key files should be found, if different
   than the current working directory. (Note that this option has no
   effect on the paths for files containing non-DNSSEC keys such as
   ``bind.keys``, ``rndc.key`` or ``session.key``.)

``lmdb-mapsize``
   When ``named`` is built with liblmdb, this option sets a maximum size
   for the memory map of the new-zone database (NZD) in LMDB database
   format. This database is used to store configuration information for
   zones added using ``rndc addzone``. Note that this is not the NZD
   database file size, but the largest size that the database may grow
   to.

   Because the database file is memory mapped, its size is limited by
   the address space of the named process. The default of 32 megabytes
   was chosen to be usable with 32-bit ``named`` builds. The largest
   permitted value is 1 terabyte. Given typical zone configurations
   without elaborate ACLs, a 32 MB NZD file ought to be able to hold
   configurations of about 100,000 zones.

``managed-keys-directory``
   Specifies the directory in which to store the files that track managed DNSSEC
   keys (i.e., those configured using the ``initial-key`` or ``initial-ds``
   keywords in a ``trust-anchors`` statement). By default, this is the working
   directory. The directory *must* be writable by the effective user ID of the
   ``named`` process.

   If ``named`` is not configured to use views, then managed keys for
   the server will be tracked in a single file called
   ``managed-keys.bind``. Otherwise, managed keys will be tracked in
   separate files, one file per view; each file name will be the view
   name (or, if it contains characters that are incompatible with use as
   a file name, the SHA256 hash of the view name), followed by the
   extension ``.mkeys``.

   (Note: in previous releases, file names for views always used the
   SHA256 hash of the view name. To ensure compatibility after upgrade,
   if a file using the old name format is found to exist, it will be
   used instead of the new format.)

``max-ixfr-ratio``
   Sets the size threshold (expressed as a percentage of the size of the full
   zone) beyond which ``named`` will choose to use an AXFR response rather than
   IXFR when answering zone transfer requests.  See
   :ref:`incremental_zone_transfers`.

``new-zones-directory``
   Specifies the directory in which to store the configuration
   parameters for zones added via ``rndc addzone``. By default, this is
   the working directory. If set to a relative path, it will be relative
   to the working directory. The directory *must* be writable by the
   effective user ID of the ``named`` process.

``qname-minimization``
   This option controls QNAME minimization behaviour in the BIND
   resolver. When set to ``strict``, BIND will follow the QNAME
   minimization algorithm to the letter, as specified in :rfc:`7816`.
   Setting this option to ``relaxed`` will cause BIND to fall back to
   normal (non-minimized) query mode when it receives either NXDOMAIN or
   other unexpected responses (e.g. SERVFAIL, improper zone cut,
   REFUSED) to a minimized query. ``disabled`` disables QNAME
   minimization completely. The current default is ``relaxed``, but it
   might be changed to ``strict`` in a future release.

``tkey-gssapi-keytab``
   The KRB5 keytab file to use for GSS-TSIG updates. If this option is
   set and tkey-gssapi-credential is not set, then updates will be
   allowed with any key matching a principal in the specified keytab.

``tkey-gssapi-credential``
   The security credential with which the server should authenticate
   keys requested by the GSS-TSIG protocol. Currently only Kerberos 5
   authentication is available and the credential is a Kerberos
   principal which the server can acquire through the default system key
   file, normally ``/etc/krb5.keytab``. The location keytab file can be
   overridden using the tkey-gssapi-keytab option. Normally this
   principal is of the form "``DNS/``\ ``server.domain``". To use
   GSS-TSIG, ``tkey-domain`` must also be set if a specific keytab is
   not set with tkey-gssapi-keytab.

``tkey-domain``
   The domain appended to the names of all shared keys generated with
   ``TKEY``. When a client requests a ``TKEY`` exchange, it may or may
   not specify the desired name for the key. If present, the name of the
   shared key will be ``client specified part`` + ``tkey-domain``.
   Otherwise, the name of the shared key will be ``random hex digits``
   + ``tkey-domain``. In most cases, the ``domainname``
   should be the server's domain name, or an otherwise non-existent
   subdomain like "_tkey.``domainname``". If you are using GSS-TSIG,
   this variable must be defined, unless you specify a specific keytab
   using tkey-gssapi-keytab.

``tkey-dhkey``
   The Diffie-Hellman key used by the server to generate shared keys
   with clients using the Diffie-Hellman mode of ``TKEY``. The server
   must be able to load the public and private keys from files in the
   working directory. In most cases, the ``key_name`` should be the
   server's host name.

``cache-file``
   This is for testing only. Do not use.

``dump-file``
   The pathname of the file the server dumps the database to when
   instructed to do so with ``rndc dumpdb``. If not specified, the
   default is ``named_dump.db``.

``memstatistics-file``
   The pathname of the file the server writes memory usage statistics to
   on exit. If not specified, the default is ``named.memstats``.

``lock-file``
   The pathname of a file on which ``named`` will attempt to acquire a
   file lock when starting up for the first time; if unsuccessful, the
   server will will terminate, under the assumption that another server
   is already running. If not specified, the default is
   ``none``.

   Specifying ``lock-file none`` disables the use of a lock file.
   ``lock-file`` is ignored if ``named`` was run using the ``-X``
   option, which overrides it. Changes to ``lock-file`` are ignored if
   ``named`` is being reloaded or reconfigured; it is only effective
   when the server is first started up.

``pid-file``
   The pathname of the file the server writes its process ID in. If not
   specified, the default is ``/var/run/named/named.pid``. The PID file
   is used by programs that want to send signals to the running name
   server. Specifying ``pid-file none`` disables the use of a PID file —
   no file will be written and any existing one will be removed. Note
   that ``none`` is a keyword, not a filename, and therefore is not
   enclosed in double quotes.

``recursing-file``
   The pathname of the file the server dumps the queries that are
   currently recursing when instructed to do so with ``rndc recursing``.
   If not specified, the default is ``named.recursing``.

``statistics-file``
   The pathname of the file the server appends statistics to when
   instructed to do so using ``rndc stats``. If not specified, the
   default is ``named.stats`` in the server's current directory. The
   format of the file is described in :ref:`statsfile`.

``bindkeys-file``
   The pathname of a file to override the built-in trusted keys provided
   by ``named``. See the discussion of ``dnssec-validation`` for
   details. If not specified, the default is ``/etc/bind.keys``.

``secroots-file``
   The pathname of the file the server dumps security roots to when
   instructed to do so with ``rndc secroots``. If not specified, the
   default is ``named.secroots``.

``session-keyfile``
   The pathname of the file into which to write a TSIG session key
   generated by ``named`` for use by ``nsupdate -l``. If not specified,
   the default is ``/var/run/named/session.key``. (See :ref:`dynamic_update_policies`,
   and in particular the discussion of the ``update-policy`` statement's
   ``local`` option for more information about this feature.)

``session-keyname``
   The key name to use for the TSIG session key. If not specified, the
   default is "local-ddns".

``session-keyalg``
   The algorithm to use for the TSIG session key. Valid values are
   hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512 and
   hmac-md5. If not specified, the default is hmac-sha256.

``port``
   The UDP/TCP port number the server uses for receiving and sending DNS
   protocol traffic. The default is 53. This option is mainly intended
   for server testing; a server using a port other than 53 will not be
   able to communicate with the global DNS.

``dscp``
   The global Differentiated Services Code Point (DSCP) value to
   classify outgoing DNS traffic on operating systems that support DSCP.
   Valid values are 0 through 63. It is not configured by default.

``random-device``
   Specifies a source of entropy to be used by the server. This is a
   device or file from which to read entropy. If it is a file,
   operations requiring entropy will fail when the file has been
   exhausted.

   Entropy is needed for cryptographic operations such as TKEY
   transactions, dynamic update of signed zones, and generation of TSIG
   session keys. It is also used for seeding and stirring the
   pseudo-random number generator, which is used for less critical
   functions requiring randomness such as generation of DNS message
   transaction ID's.

   If ``random-device`` is not specified, or if it is set to ``none``,
   entropy will be read from the random number generation function
   supplied by the cryptographic library with which BIND was linked
   (i.e. OpenSSL or a PKCS#11 provider).

   The ``random-device`` option takes effect during the initial
   configuration load at server startup time and is ignored on
   subsequent reloads.

``preferred-glue``
   If specified, the listed type (A or AAAA) will be emitted before
   other glue in the additional section of a query response. The default
   is to prefer A records when responding to queries that arrived via
   IPv4 and AAAA when responding to queries that arrived via IPv6.

.. _root-delegation-only:

``root-delegation-only``
   Turn on enforcement of delegation-only in TLDs (top level domains)
   and root zones with an optional exclude list.

   DS queries are expected to be made to and be answered by delegation
   only zones. Such queries and responses are treated as an exception to
   delegation-only processing and are not converted to NXDOMAIN
   responses provided a CNAME is not discovered at the query name.

   If a delegation only zone server also serves a child zone it is not
   always possible to determine whether an answer comes from the
   delegation only zone or the child zone. SOA NS and DNSKEY records are
   apex only records and a matching response that contains these records
   or DS is treated as coming from a child zone. RRSIG records are also
   examined to see if they are signed by a child zone or not. The
   authority section is also examined to see if there is evidence that
   the answer is from the child zone. Answers that are determined to be
   from a child zone are not converted to NXDOMAIN responses. Despite
   all these checks there is still a possibility of false negatives when
   a child zone is being served.

   Similarly false positives can arise from empty nodes (no records at
   the name) in the delegation only zone when the query type is not ANY.

   Note some TLDs are not delegation only (e.g. "DE", "LV", "US" and
   "MUSEUM"). This list is not exhaustive.

   ::

      options {
          root-delegation-only exclude { "de"; "lv"; "us"; "museum"; };
      };

``disable-algorithms``
   Disable the specified DNSSEC algorithms at and below the specified
   name. Multiple ``disable-algorithms`` statements are allowed. Only
   the best match ``disable-algorithms`` clause will be used to
   determine which algorithms are used.

   If all supported algorithms are disabled, the zones covered by the
   ``disable-algorithms`` will be treated as insecure.

   Configured trust anchors in ``trusted-anchors`` (or ``managed-keys`` or
   ``trusted-keys``) that match a disabled algorithm will be ignored and treated
   as if they were not configured at all.

``disable-ds-digests``
   Disable the specified DS digest types at and below the specified
   name. Multiple ``disable-ds-digests`` statements are allowed. Only
   the best match ``disable-ds-digests`` clause will be used to
   determine which digest types are used.

   If all supported digest types are disabled, the zones covered by the
   ``disable-ds-digests`` will be treated as insecure.

``dnssec-must-be-secure``
   Specify hierarchies which must be or may not be secure (signed and
   validated). If ``yes``, then ``named`` will only accept answers if
   they are secure. If ``no``, then normal DNSSEC validation applies
   allowing for insecure answers to be accepted. The specified domain
   must be defined as a trust anchor, for instance in a ``trust-anchors``
   statement, or ``dnssec-validation auto`` must be active.

``dns64``
   This directive instructs ``named`` to return mapped IPv4 addresses to
   AAAA queries when there are no AAAA records. It is intended to be
   used in conjunction with a NAT64. Each ``dns64`` defines one DNS64
   prefix. Multiple DNS64 prefixes can be defined.

   Compatible IPv6 prefixes have lengths of 32, 40, 48, 56, 64 and 96 as per
   :rfc:`6052`. Bits 64..71 inclusive must be zero with the most significate bit
   of the prefix in position 0.

   Additionally a reverse IP6.ARPA zone will be created for the prefix
   to provide a mapping from the IP6.ARPA names to the corresponding
   IN-ADDR.ARPA names using synthesized CNAMEs. ``dns64-server`` and
   ``dns64-contact`` can be used to specify the name of the server and
   contact for the zones. These are settable at the view / options
   level. These are not settable on a per-prefix basis.

   Each ``dns64`` supports an optional ``clients`` ACL that determines
   which clients are affected by this directive. If not defined, it
   defaults to ``any;``.

   Each ``dns64`` supports an optional ``mapped`` ACL that selects which
   IPv4 addresses are to be mapped in the corresponding A RRset. If not
   defined it defaults to ``any;``.

   Normally, DNS64 won't apply to a domain name that owns one or more
   AAAA records; these records will simply be returned. The optional
   ``exclude`` ACL allows specification of a list of IPv6 addresses that
   will be ignored if they appear in a domain name's AAAA records, and
   DNS64 will be applied to any A records the domain name owns. If not
   defined, ``exclude`` defaults to ::ffff:0.0.0.0/96.

   A optional ``suffix`` can also be defined to set the bits trailing
   the mapped IPv4 address bits. By default these bits are set to
   ``::``. The bits matching the prefix and mapped IPv4 address must be
   zero.

   If ``recursive-only`` is set to ``yes`` the DNS64 synthesis will only
   happen for recursive queries. The default is ``no``.

   If ``break-dnssec`` is set to ``yes`` the DNS64 synthesis will happen
   even if the result, if validated, would cause a DNSSEC validation
   failure. If this option is set to ``no`` (the default), the DO is set
   on the incoming query, and there are RRSIGs on the applicable
   records, then synthesis will not happen.

   ::

          acl rfc1918 { 10/8; 192.168/16; 172.16/12; };

          dns64 64:FF9B::/96 {
              clients { any; };
              mapped { !rfc1918; any; };
              exclude { 64:FF9B::/96; ::ffff:0000:0000/96; };
              suffix ::;
          };

``dnssec-loadkeys-interval``
   When a zone is configured with ``auto-dnssec maintain;`` its key
   repository must be checked periodically to see if any new keys have
   been added or any existing keys' timing metadata has been updated
   (see :ref:`man_dnssec-keygen` and :ref:`man_dnssec-settime`).
   The ``dnssec-loadkeys-interval`` option
   sets the frequency of automatic repository checks, in minutes.  The
   default is ``60`` (1 hour), the minimum is ``1`` (1 minute), and
   the maximum is ``1440`` (24 hours); any higher value is silently
   reduced.

``dnssec-policy``
   Specifies which key and signing policy (KASP) should be used for this zone.
   This is a string referring to a ``dnssec-policy`` statement.  There are two
   built-in policies: ``default`` allows you to use the default policy, and
   ``none`` means not to use any DNSSEC policy, keeping the zone unsigned.  The
   default is ``none``.  See :ref:`dnssec-policy Grammar
   <dnssec_policy_grammar>` for more details.

``dnssec-update-mode``
   If this option is set to its default value of ``maintain`` in a zone
   of type ``master`` which is DNSSEC-signed and configured to allow
   dynamic updates (see :ref:`dynamic_update_policies`), and if ``named`` has access
   to the private signing key(s) for the zone, then ``named`` will
   automatically sign all new or changed records and maintain signatures
   for the zone by regenerating RRSIG records whenever they approach
   their expiration date.

   If the option is changed to ``no-resign``, then ``named`` will sign
   all new or changed records, but scheduled maintenance of signatures
   is disabled.

   With either of these settings, ``named`` will reject updates to a
   DNSSEC-signed zone when the signing keys are inactive or unavailable
   to ``named``. (A planned third option, ``external``, will disable all
   automatic signing and allow DNSSEC data to be submitted into a zone
   via dynamic update; this is not yet implemented.)

``nta-lifetime``
   Species the default lifetime, in seconds, that will be used for
   negative trust anchors added via ``rndc nta``.

   A negative trust anchor selectively disables DNSSEC validation for
   zones that are known to be failing because of misconfiguration rather
   than an attack. When data to be validated is at or below an active
   NTA (and above any other configured trust anchors), ``named`` will
   abort the DNSSEC validation process and treat the data as insecure
   rather than bogus. This continues until the NTA's lifetime is
   elapsed. NTAs persist across ``named`` restarts.

   For convenience, TTL-style time unit suffixes can be used to specify the NTA
   lifetime in seconds, minutes or hours. It also accepts ISO 8601 duration
   formats.

   ``nta-lifetime`` defaults to one hour. It cannot exceed one week.

``nta-recheck``
   Species how often to check whether negative trust anchors added via
   ``rndc nta`` are still necessary.

   A negative trust anchor is normally used when a domain has stopped
   validating due to operator error; it temporarily disables DNSSEC
   validation for that domain. In the interest of ensuring that DNSSEC
   validation is turned back on as soon as possible, ``named`` will
   periodically send a query to the domain, ignoring negative trust
   anchors, to find out whether it can now be validated. If so, the
   negative trust anchor is allowed to expire early.

   Validity checks can be disabled for an individual NTA by using
   ``rndc nta -f``, or for all NTAs by setting ``nta-recheck`` to zero.

   For convenience, TTL-style time unit suffixes can be used to specify the NTA
   recheck interval in seconds, minutes or hours. It also accepts ISO 8601
   duration formats.

   The default is five minutes. It cannot be longer than ``nta-lifetime`` (which
   cannot be longer than a week).

``max-zone-ttl``
   Specifies a maximum permissible TTL value in seconds. For
   convenience, TTL-style time unit suffixes may be used to specify the
   maximum value. When loading a zone file using a ``masterfile-format``
   of ``text`` or ``raw``, any record encountered with a TTL higher than
   ``max-zone-ttl`` will cause the zone to be rejected.

   This is useful in DNSSEC-signed zones because when rolling to a new
   DNSKEY, the old key needs to remain available until RRSIG records
   have expired from caches. The ``max-zone-ttl`` option guarantees that
   the largest TTL in the zone will be no higher than the set value.

   (NOTE: Because ``map``-format files load directly into memory, this
   option cannot be used with them.)

   The default value is ``unlimited``. A ``max-zone-ttl`` of zero is
   treated as ``unlimited``.

``stale-answer-ttl``
   Specifies the TTL to be returned on stale answers. The default is 1
   second. The minimum allowed is also 1 second; a value of 0 will be
   updated silently to 1 second.

   For stale answers to be returned, they must be enabled, either in the
   configuration file using ``stale-answer-enable`` or via
   ``rndc serve-stale on``.

``serial-update-method``
   Zones configured for dynamic DNS may use this option to set the
   update method that will be used for the zone serial number in the SOA
   record.

   With the default setting of ``serial-update-method increment;``, the
   SOA serial number will be incremented by one each time the zone is
   updated.

   When set to ``serial-update-method unixtime;``, the SOA serial number
   will be set to the number of seconds since the UNIX epoch, unless the
   serial number is already greater than or equal to that value, in
   which case it is simply incremented by one.

   When set to ``serial-update-method date;``, the new SOA serial number
   will be the current date in the form "YYYYMMDD", followed by two
   zeroes, unless the existing serial number is already greater than or
   equal to that value, in which case it is incremented by one.

``zone-statistics``
   If ``full``, the server will collect statistical data on all zones
   (unless specifically turned off on a per-zone basis by specifying
   ``zone-statistics terse`` or ``zone-statistics none`` in the ``zone``
   statement). The default is ``terse``, providing minimal statistics on
   zones (including name and current serial number, but not query type
   counters).

   These statistics may be accessed via the ``statistics-channel`` or
   using ``rndc stats``, which will dump them to the file listed in the
   ``statistics-file``. See also :ref:`statsfile`.

   For backward compatibility with earlier versions of BIND 9, the
   ``zone-statistics`` option can also accept ``yes`` or ``no``; ``yes``
   has the same meaning as ``full``. As of BIND 9.10, ``no`` has the
   same meaning as ``none``; previously, it was the same as ``terse``.

.. _boolean_options:

Boolean Options
^^^^^^^^^^^^^^^

``automatic-interface-scan``

   If ``yes`` and and supported by the operating system, automatically rescan
   network interfaces when the interface addresses are added or removed.  The
   default is ``yes``.  This configuration option does not affect time based
   ``interface-interval`` option, and it is recommended to set the time based
   ``interface-interval`` to 0 when the operator confirms that automatic
   interface scanning is supported by the operating system.

   The ``automatic-interface-scan`` implementation uses routing sockets for the
   network interface discovery, and therefore the operating system has to
   support the routing sockets for this feature to work.

``allow-new-zones``
   If ``yes``, then zones can be added at runtime via ``rndc addzone``.
   The default is ``no``.

   Newly added zones' configuration parameters are stored so that they
   can persist after the server is restarted. The configuration
   information is saved in a file called ``viewname.nzf`` (or, if
   ``named`` is compiled with liblmdb, in an LMDB database file called
   ``viewname.nzd``). viewname is the name of the view, unless the view
   name contains characters that are incompatible with use as a file
   name, in which case a cryptographic hash of the view name is used
   instead.

   Zones added at runtime will have their configuration stored either in
   a new-zone file (NZF) or a new-zone database (NZD) depending on
   whether ``named`` was linked with liblmdb at compile time. See
   :ref:`man_rndc` for further details about ``rndc addzone``.

``auth-nxdomain``
   If ``yes``, then the ``AA`` bit is always set on NXDOMAIN responses,
   even if the server is not actually authoritative. The default is
   ``no``. If you are using very old DNS software, you may need to set
   it to ``yes``.

``deallocate-on-exit``
   This option was used in BIND 8 to enable checking for memory leaks on
   exit. BIND 9 ignores the option and always performs the checks.

``memstatistics``
   Write memory statistics to the file specified by
   ``memstatistics-file`` at exit. The default is ``no`` unless '-m
   record' is specified on the command line in which case it is ``yes``.

``dialup``
   If ``yes``, then the server treats all zones as if they are doing
   zone transfers across a dial-on-demand dialup link, which can be
   brought up by traffic originating from this server. This has
   different effects according to zone type and concentrates the zone
   maintenance so that it all happens in a short interval, once every
   ``heartbeat-interval`` and hopefully during the one call. It also
   suppresses some of the normal zone maintenance traffic. The default
   is ``no``.

   The ``dialup`` option may also be specified in the ``view`` and
   ``zone`` statements, in which case it overrides the global ``dialup``
   option.

   If the zone is a master zone, then the server will send out a NOTIFY
   request to all the slaves (default). This should trigger the zone
   serial number check in the slave (providing it supports NOTIFY)
   allowing the slave to verify the zone while the connection is active.
   The set of servers to which NOTIFY is sent can be controlled by
   ``notify`` and ``also-notify``.

   If the zone is a slave or stub zone, then the server will suppress
   the regular "zone up to date" (refresh) queries and only perform them
   when the ``heartbeat-interval`` expires in addition to sending NOTIFY
   requests.

   Finer control can be achieved by using ``notify`` which only sends
   NOTIFY messages, ``notify-passive`` which sends NOTIFY messages and
   suppresses the normal refresh queries, ``refresh`` which suppresses
   normal refresh processing and sends refresh queries when the
   ``heartbeat-interval`` expires, and ``passive`` which just disables
   normal refresh processing.

   +--------------------+-----------------+-----------------+-----------------+
   | dialup mode        | normal refresh  | heart-beat      | heart-beat      |
   |                    |                 | refresh         | notify          |
   +--------------------+-----------------+-----------------+-----------------+
   | ``no``             | yes             | no              | no              |
   | (default)          |                 |                 |                 |
   +--------------------+-----------------+-----------------+-----------------+
   | ``yes``            | no              | yes             | yes             |
   +--------------------+-----------------+-----------------+-----------------+
   | ``notify``         | yes             | no              | yes             |
   +--------------------+-----------------+-----------------+-----------------+
   | ``refresh``        | no              | yes             | no              |
   +--------------------+-----------------+-----------------+-----------------+
   | ``passive``        | no              | no              | no              |
   +--------------------+-----------------+-----------------+-----------------+
   | ``notify-passive`` | no              | no              | yes             |
   +--------------------+-----------------+-----------------+-----------------+

   Note that normal NOTIFY processing is not affected by ``dialup``.

``flush-zones-on-shutdown``
   When the nameserver exits due receiving SIGTERM, flush or do not
   flush any pending zone writes. The default is
   ``flush-zones-on-shutdown`` ``no``.

``geoip-use-ecs``
   This option was part of an experimental implementation of the EDNS
   CLIENT-SUBNET for authoritative servers, but is now obsolete.

``root-key-sentinel``
   Respond to root key sentinel probes as described in
   draft-ietf-dnsop-kskroll-sentinel-08. The default is ``yes``.

``message-compression``
   If ``yes``, DNS name compression is used in responses to regular
   queries (not including AXFR or IXFR, which always uses compression).
   Setting this option to ``no`` reduces CPU usage on servers and may
   improve throughput. However, it increases response size, which may
   cause more queries to be processed using TCP; a server with
   compression disabled is out of compliance with :rfc:`1123` Section
   6.1.3.2. The default is ``yes``.

``minimal-responses``
   This option controls the addition of records to the authority and
   additional sections of responses. Such records may be included in
   responses to be helpful to clients; for example, NS or MX records may
   have associated address records included in the additional section,
   obviating the need for a separate address lookup. However, adding
   these records to responses is not mandatory and requires additional
   database lookups, causing extra latency when marshalling responses.
   ``minimal-responses`` takes one of four values:

   -  ``no``: the server will be as complete as possible when generating
      responses.
   -  ``yes``: the server will only add records to the authority and additional
      sections when such records are required by the DNS protocol (for
      example, when returning delegations or negative responses). This
      provides the best server performance but may result in more client
      queries.
   -  ``no-auth``: the server will omit records from the authority section except
      when they are required, but it may still add records to the
      additional section.
   -  ``no-auth-recursive``: the same as ``no-auth`` when recursion is requested
      in the query (RD=1), or the same as ``no`` if recursion is not requested.

   ``no-auth`` and ``no-auth-recursive`` are useful when answering stub
   clients, which usually ignore the authority section.
   ``no-auth-recursive`` is meant for use in mixed-mode servers that
   handle both authoritative and recursive queries.

   The default is ``no-auth-recursive``.

``glue-cache``
   When set to ``yes``, a cache is used to improve query performance
   when adding address-type (A and AAAA) glue records to the additional
   section of DNS response messages that delegate to a child zone.

   The glue cache uses memory proportional to the number of delegations
   in the zone. The default setting is ``yes``, which improves
   performance at the cost of increased memory usage for the zone. If
   you don't want this, set it to ``no``.

``minimal-any``
   If set to ``yes``, then when generating a positive response to a
   query of type ANY over UDP, the server will reply with only one of
   the RRsets for the query name, and its covering RRSIGs if any,
   instead of replying with all known RRsets for the name. Similarly, a
   query for type RRSIG will be answered with the RRSIG records covering
   only one type. This can reduce the impact of some kinds of attack
   traffic, without harming legitimate clients. (Note, however, that the
   RRset returned is the first one found in the database; it is not
   necessarily the smallest available RRset.) Additionally,
   ``minimal-responses`` is turned on for these queries, so no
   unnecessary records will be added to the authority or additional
   sections. The default is ``no``.

``notify``
   If ``yes`` (the default), DNS NOTIFY messages are sent when a zone
   the server is authoritative for changes, see :ref:`notify`.
   The messages are sent to the servers listed in the zone's NS records
   (except the master server identified in the SOA MNAME field), and to
   any servers listed in the ``also-notify`` option.

   If ``master-only``, notifies are only sent for master zones. If
   ``explicit``, notifies are sent only to servers explicitly listed
   using ``also-notify``. If ``no``, no notifies are sent.

   The ``notify`` option may also be specified in the ``zone``
   statement, in which case it overrides the ``options notify``
   statement. It would only be necessary to turn off this option if it
   caused slaves to crash.

``notify-to-soa``
   If ``yes`` do not check the nameservers in the NS RRset against the
   SOA MNAME. Normally a NOTIFY message is not sent to the SOA MNAME
   (SOA ORIGIN) as it is supposed to contain the name of the ultimate
   master. Sometimes, however, a slave is listed as the SOA MNAME in
   hidden master configurations and in that case you would want the
   ultimate master to still send NOTIFY messages to all the nameservers
   listed in the NS RRset.

``recursion``
   If ``yes``, and a DNS query requests recursion, then the server will
   attempt to do all the work required to answer the query. If recursion
   is off and the server does not already know the answer, it will
   return a referral response. The default is ``yes``. Note that setting
   ``recursion no`` does not prevent clients from getting data from the
   server's cache; it only prevents new data from being cached as an
   effect of client queries. Caching may still occur as an effect the
   server's internal operation, such as NOTIFY address lookups.

``request-nsid``
   If ``yes``, then an empty EDNS(0) NSID (Name Server Identifier)
   option is sent with all queries to authoritative name servers during
   iterative resolution. If the authoritative server returns an NSID
   option in its response, then its contents are logged in the ``nsid``
   category at level ``info``. The default is ``no``.

``request-sit``
   This experimental option is obsolete.

``require-server-cookie``
   Require a valid server cookie before sending a full response to a UDP
   request from a cookie aware client. BADCOOKIE is sent if there is a
   bad or no existent server cookie.

   The default is ``no``.

   Set this to ``yes`` to test that DNS COOKIE clients correctly handle
   BADCOOKIE or if you are getting a lot of forged DNS requests with DNS COOKIES
   present. Setting this to ``yes`` will result in reduced amplification effect
   in a reflection attack, as the BADCOOKIE response will be smaller than a full
   response, while also requiring a legitimate client to follow up with a second
   query with the new, valid, cookie.

``answer-cookie``
   When set to the default value of ``yes``, COOKIE EDNS options will be
   sent when applicable in replies to client queries. If set to ``no``,
   COOKIE EDNS options will not be sent in replies. This can only be set
   at the global options level, not per-view.

   ``answer-cookie no`` is intended as a temporary measure, for use when
   ``named`` shares an IP address with other servers that do not yet
   support DNS COOKIE. A mismatch between servers on the same address is
   not expected to cause operational problems, but the option to disable
   COOKIE responses so that all servers have the same behavior is
   provided out of an abundance of caution. DNS COOKIE is an important
   security mechanism, and should not be disabled unless absolutely
   necessary.

``send-cookie``
   If ``yes``, then a COOKIE EDNS option is sent along with the query.
   If the resolver has previously talked to the server, the COOKIE
   returned in the previous transaction is sent. This is used by the
   server to determine whether the resolver has talked to it before. A
   resolver sending the correct COOKIE is assumed not to be an off-path
   attacker sending a spoofed-source query; the query is therefore
   unlikely to be part of a reflection/amplification attack, so
   resolvers sending a correct COOKIE option are not subject to response
   rate limiting (RRL). Resolvers which do not send a correct COOKIE
   option may be limited to receiving smaller responses via the
   ``nocookie-udp-size`` option.

   The default is ``yes``.

``stale-answer-enable``
   Enable the returning of "stale" cached answers when the nameservers
   for a zone are not answering. The default is not to return stale
   answers.

   Stale answers can also be enabled or disabled at runtime via
   ``rndc serve-stale on`` or ``rndc serve-stale off``; these override
   the configured setting. ``rndc serve-stale reset`` restores the
   setting to the one specified in ``named.conf``. Note that if stale
   answers have been disabled by ``rndc``, then they cannot be
   re-enabled by reloading or reconfiguring ``named``; they must be
   re-enabled with ``rndc serve-stale on``, or the server must be
   restarted.

   Information about stale answers is logged under the ``serve-stale``
   log category.

``nocookie-udp-size``
   Sets the maximum size of UDP responses that will be sent to queries
   without a valid server COOKIE. A value below 128 will be silently
   raised to 128. The default value is 4096, but the ``max-udp-size``
   option may further limit the response size.

``sit-secret``
   This experimental option is obsolete.

``cookie-algorithm``
   Set the algorithm to be used when generating the server cookie. One
   of "aes", "sha1" or "sha256". The default is "aes" if supported by
   the cryptographic library or otherwise "sha256".

``cookie-secret``
   If set, this is a shared secret used for generating and verifying
   EDNS COOKIE options within an anycast cluster. If not set, the system
   will generate a random secret at startup. The shared secret is
   encoded as a hex string and needs to be 128 bits for AES128, 160 bits
   for SHA1 and 256 bits for SHA256.

   If there are multiple secrets specified, the first one listed in
   ``named.conf`` is used to generate new server cookies. The others
   will only be used to verify returned cookies.

``response-padding``
   The EDNS Padding option is intended to improve confidentiality when
   DNS queries are sent over an encrypted channel by reducing the
   variability in packet sizes. If a query:

   1. contains an EDNS Padding option,
   2. includes a valid server cookie or uses TCP,
   3. is not signed using TSIG or SIG(0), and
   4. is from a client whose address matches the specified ACL,

   then the response is padded with an EDNS Padding option to a multiple
   of ``block-size`` bytes. If these conditions are not met, the
   response is not padded.

   If ``block-size`` is 0 or the ACL is ``none;``, then this feature is
   disabled and no padding will occur; this is the default. If
   ``block-size`` is greater than 512, a warning is logged and the value
   is truncated to 512. Block sizes are ordinarily expected to be powers
   of two (for instance, 128), but this is not mandatory.

``trust-anchor-telemetry``
   Causes ``named`` to send specially-formed queries once per day to
   domains for which trust anchors have been configured via, e.g.,
   ``dnssec-keys`` or ``dnssec-validation auto``.

   The query name used for these queries has the form
   "_ta-xxxx(-xxxx)(...)".<domain>, where each "xxxx" is a group of four
   hexadecimal digits representing the key ID of a trusted DNSSEC key.
   The key IDs for each domain are sorted smallest to largest prior to
   encoding. The query type is NULL.

   By monitoring these queries, zone operators will be able to see which
   resolvers have been updated to trust a new key; this may help them
   decide when it is safe to remove an old one.

   The default is ``yes``.

``use-ixfr``
   *This option is obsolete*. If you need to disable IXFR to a
   particular server or servers, see the information on the
   ``provide-ixfr`` option in :ref:`server_statement_definition_and_usage`.
   See also :ref:`incremental_zone_transfers`.

``provide-ixfr``
   See the description of ``provide-ixfr`` in :ref:`server_statement_definition_and_usage`.

``request-ixfr``
   See the description of ``request-ixfr`` in :ref:`server_statement_definition_and_usage`.

``request-expire``
   See the description of ``request-expire`` in :ref:`server_statement_definition_and_usage`.

``match-mapped-addresses``
   If ``yes``, then an IPv4-mapped IPv6 address will match any address
   match list entries that match the corresponding IPv4 address.

   This option was introduced to work around a kernel quirk in some
   operating systems that causes IPv4 TCP connections, such as zone
   transfers, to be accepted on an IPv6 socket using mapped addresses.
   This caused address match lists designed for IPv4 to fail to match.
   However, ``named`` now solves this problem internally. The use of
   this option is discouraged.

``ixfr-from-differences``
   When ``yes`` and the server loads a new version of a master zone from
   its zone file or receives a new version of a slave file via zone
   transfer, it will compare the new version to the previous one and
   calculate a set of differences. The differences are then logged in
   the zone's journal file such that the changes can be transmitted to
   downstream slaves as an incremental zone transfer.

   By allowing incremental zone transfers to be used for non-dynamic
   zones, this option saves bandwidth at the expense of increased CPU
   and memory consumption at the master. In particular, if the new
   version of a zone is completely different from the previous one, the
   set of differences will be of a size comparable to the combined size
   of the old and new zone version, and the server will need to
   temporarily allocate memory to hold this complete difference set.

   ``ixfr-from-differences`` also accepts ``master`` (or ``primary``)
   and ``slave`` (or ``secondary``) at the view and options levels,
   which causes ``ixfr-from-differences`` to be enabled for all primary
   or secondary zones, respectively. It is off for all zones by default.

   Note: if inline signing is enabled for a zone, the user-provided
   ``ixfr-from-differences`` setting is ignored for that zone.

``multi-master``
   This should be set when you have multiple masters for a zone and the
   addresses refer to different machines. If ``yes``, ``named`` will not
   log when the serial number on the master is less than what ``named``
   currently has. The default is ``no``.

``auto-dnssec``
   Zones configured for dynamic DNS may use this option to allow varying
   levels of automatic DNSSEC key management. There are three possible
   settings:

   ``auto-dnssec allow;`` permits keys to be updated and the zone fully
   re-signed whenever the user issues the command ``rndc sign zonename``.

   ``auto-dnssec maintain;`` includes the above, but also
   automatically adjusts the zone's DNSSEC keys on schedule, according
   to the keys' timing metadata (see :ref:`man_dnssec-keygen` and
   :ref:`man_dnssec-settime`). The command ``rndc sign zonename``
   causes ``named`` to load keys from the key repository and sign the
   zone with all keys that are active.  ``rndc loadkeys zonename``
   causes ``named`` to load keys from the key repository and schedule
   key maintenance events to occur in the future, but it does not sign
   the full zone immediately. Note: once keys have been loaded for a
   zone the first time, the repository will be searched for changes
   periodically, regardless of whether ``rndc loadkeys`` is used. The
   recheck interval is defined by ``dnssec-loadkeys-interval``.)

   The default setting is ``auto-dnssec off``.

``dnssec-enable``
   This option is obsolete and has no effect.

.. _dnssec-validation-option:

``dnssec-validation``
   This option enables DNSSEC validation in ``named``.

   If set to ``auto``, DNSSEC validation is enabled, and a default trust
   anchor for the DNS root zone is used.

   If set to ``yes``, DNSSEC validation is enabled, but a trust anchor must be
   manually configured using a ``trust-anchors`` statement (or the
   ``managed-keys``, or the ``trusted-keys`` statements, both deprecated). If
   there is no configured trust anchor, validation will not take place.

   If set to ``no``, DNSSEC validation is disabled.

   The default is ``auto``, unless BIND is built with
   ``configure --disable-auto-validation``, in which case the default is
   ``yes``.

   The default root trust anchor is stored in the file ``bind.keys``.
   ``named`` will load that key at startup if ``dnssec-validation`` is
   set to ``auto``. A copy of the file is installed along with BIND 9,
   and is current as of the release date. If the root key expires, a new
   copy of ``bind.keys`` can be downloaded from
   https://www.isc.org/bind-keys.

   (To prevent problems if ``bind.keys`` is not found, the current trust
   anchor is also compiled in to ``named``. Relying on this is not
   recommended, however, as it requires ``named`` to be recompiled with
   a new key when the root key expires.)

   .. note:: ``named`` loads *only* the root key from ``bind.keys``. The file
         cannot be used to store keys for other zones. The root key in
         ``bind.keys`` is ignored if ``dnssec-validation auto`` is not in
         use.

         Whenever the resolver sends out queries to an EDNS-compliant
         server, it always sets the DO bit indicating it can support DNSSEC
         responses even if ``dnssec-validation`` is off.

``validate-except``
   Specifies a list of domain names at and beneath which DNSSEC
   validation should *not* be performed, regardless of the presence of a
   trust anchor at or above those names. This may be used, for example,
   when configuring a top-level domain intended only for local use, so
   that the lack of a secure delegation for that domain in the root zone
   will not cause validation failures. (This is similar to setting a
   negative trust anchor, except that it is a permanent configuration,
   whereas negative trust anchors expire and are removed after a set
   period of time.)

``dnssec-accept-expired``
   Accept expired signatures when verifying DNSSEC signatures. The
   default is ``no``. Setting this option to ``yes`` leaves ``named``
   vulnerable to replay attacks.

``querylog``
   Query logging provides a complete log of all incoming queries and all query
   errors. This provides more insight into the server's activity, but with a
   cost to performance which may be significant on heavily-loaded servers.

   The ``querylog`` option specifies whether query logging should be active when
   ``named`` first starts.  If ``querylog`` is not specified, then query logging
   is determined by the presence of the logging category ``queries``.  Query
   logging can also be activated at runtime using the command ``rndc querylog
   on``, or deactivated with ``rndc querylog off``.

``check-names``
   This option is used to restrict the character set and syntax of
   certain domain names in master files and/or DNS responses received
   from the network. The default varies according to usage area. For
   ``master`` zones the default is ``fail``. For ``slave`` zones the
   default is ``warn``. For answers received from the network
   (``response``) the default is ``ignore``.

   The rules for legal hostnames and mail domains are derived from
   :rfc:`952` and :rfc:`821` as modified by :rfc:`1123`.

   ``check-names`` applies to the owner names of A, AAAA and MX records.
   It also applies to the domain names in the RDATA of NS, SOA, MX, and
   SRV records. It also applies to the RDATA of PTR records where the
   owner name indicated that it is a reverse lookup of a hostname (the
   owner name ends in IN-ADDR.ARPA, IP6.ARPA, or IP6.INT).

``check-dup-records``
   Check master zones for records that are treated as different by
   DNSSEC but are semantically equal in plain DNS. The default is to
   ``warn``. Other possible values are ``fail`` and ``ignore``.

``check-mx``
   Check whether the MX record appears to refer to a IP address. The
   default is to ``warn``. Other possible values are ``fail`` and
   ``ignore``.

``check-wildcard``
   This option is used to check for non-terminal wildcards. The use of
   non-terminal wildcards is almost always as a result of a failure to
   understand the wildcard matching algorithm (:rfc:`1034`). This option
   affects master zones. The default (``yes``) is to check for
   non-terminal wildcards and issue a warning.

``check-integrity``
   Perform post load zone integrity checks on master zones. This checks
   that MX and SRV records refer to address (A or AAAA) records and that
   glue address records exist for delegated zones. For MX and SRV
   records only in-zone hostnames are checked (for out-of-zone hostnames
   use ``named-checkzone``). For NS records only names below top of zone
   are checked (for out-of-zone names and glue consistency checks use
   ``named-checkzone``). The default is ``yes``.

   The use of the SPF record for publishing Sender Policy Framework is
   deprecated as the migration from using TXT records to SPF records was
   abandoned. Enabling this option also checks that a TXT Sender Policy
   Framework record exists (starts with "v=spf1") if there is an SPF
   record. Warnings are emitted if the TXT record does not exist and can
   be suppressed with ``check-spf``.

``check-mx-cname``
   If ``check-integrity`` is set then fail, warn or ignore MX records
   that refer to CNAMES. The default is to ``warn``.

``check-srv-cname``
   If ``check-integrity`` is set then fail, warn or ignore SRV records
   that refer to CNAMES. The default is to ``warn``.

``check-sibling``
   When performing integrity checks, also check that sibling glue
   exists. The default is ``yes``.

``check-spf``
   If ``check-integrity`` is set then check that there is a TXT Sender
   Policy Framework record present (starts with "v=spf1") if there is an
   SPF record present. The default is ``warn``.

``zero-no-soa-ttl``
   When returning authoritative negative responses to SOA queries set
   the TTL of the SOA record returned in the authority section to zero.
   The default is ``yes``.

``zero-no-soa-ttl-cache``
   When caching a negative response to a SOA query set the TTL to zero.
   The default is ``no``.

``update-check-ksk``
   When set to the default value of ``yes``, check the KSK bit in each
   key to determine how the key should be used when generating RRSIGs
   for a secure zone.

   Ordinarily, zone-signing keys (that is, keys without the KSK bit set)
   are used to sign the entire zone, while key-signing keys (keys with
   the KSK bit set) are only used to sign the DNSKEY RRset at the zone
   apex. However, if this option is set to ``no``, then the KSK bit is
   ignored; KSKs are treated as if they were ZSKs and are used to sign
   the entire zone. This is similar to the ``dnssec-signzone -z``
   command line option.

   When this option is set to ``yes``, there must be at least two active
   keys for every algorithm represented in the DNSKEY RRset: at least
   one KSK and one ZSK per algorithm. If there is any algorithm for
   which this requirement is not met, this option will be ignored for
   that algorithm.

``dnssec-dnskey-kskonly``
   When this option and ``update-check-ksk`` are both set to ``yes``,
   only key-signing keys (that is, keys with the KSK bit set) will be
   used to sign the DNSKEY, CDNSKEY, and CDS RRsets at the zone apex.
   Zone-signing keys (keys without the KSK bit set) will be used to sign
   the remainder of the zone, but not the DNSKEY RRset. This is similar
   to the ``dnssec-signzone -x`` command line option.

   The default is ``no``. If ``update-check-ksk`` is set to ``no``, this
   option is ignored.

``try-tcp-refresh``
   Try to refresh the zone using TCP if UDP queries fail. The default is
   ``yes``.

``dnssec-secure-to-insecure``
   Allow a dynamic zone to transition from secure to insecure (i.e.,
   signed to unsigned) by deleting all of the DNSKEY records. The
   default is ``no``. If set to ``yes``, and if the DNSKEY RRset at the
   zone apex is deleted, all RRSIG and NSEC records will be removed from
   the zone as well.

   If the zone uses NSEC3, then it is also necessary to delete the
   NSEC3PARAM RRset from the zone apex; this will cause the removal of
   all corresponding NSEC3 records. (It is expected that this
   requirement will be eliminated in a future release.)

   Note that if a zone has been configured with ``auto-dnssec maintain``
   and the private keys remain accessible in the key repository, then
   the zone will be automatically signed again the next time ``named``
   is started.

``synth-from-dnssec``
   Synthesize answers from cached NSEC, NSEC3 and other RRsets that have been
   proved to be correct using DNSSEC. The default is ``no``, but it will become
   ``yes`` again in future releases.

   .. note:: DNSSEC validation must be enabled for this option to be effective.
      This initial implementation only covers synthesis of answers from
      NSEC records. Synthesis from NSEC3 is planned for the future. This
      will also be controlled by ``synth-from-dnssec``.

Forwarding
^^^^^^^^^^

The forwarding facility can be used to create a large site-wide cache on
a few servers, reducing traffic over links to external name servers. It
can also be used to allow queries by servers that do not have direct
access to the Internet, but wish to look up exterior names anyway.
Forwarding occurs only on those queries for which the server is not
authoritative and does not have the answer in its cache.

``forward``
   This option is only meaningful if the forwarders list is not empty. A
   value of ``first``, the default, causes the server to query the
   forwarders first — and if that doesn't answer the question, the
   server will then look for the answer itself. If ``only`` is
   specified, the server will only query the forwarders.

``forwarders``
   Specifies a list of IP addresses to which queries shall be forwarded. The
   default is the empty list (no forwarding).  Each address in the list can be
   associated with an optional port number and/or DSCP value, and a default port
   number and DSCP value can be set for the entire list.

Forwarding can also be configured on a per-domain basis, allowing for
the global forwarding options to be overridden in a variety of ways. You
can set particular domains to use different forwarders, or have a
different ``forward only/first`` behavior, or not forward at all, see
:ref:`zone_statement_grammar`.

.. _dual_stack:

Dual-stack Servers
^^^^^^^^^^^^^^^^^^

Dual-stack servers are used as servers of last resort to work around
problems in reachability due the lack of support for either IPv4 or IPv6
on the host machine.

``dual-stack-servers``
   Specifies host names or addresses of machines with access to both
   IPv4 and IPv6 transports. If a hostname is used, the server must be
   able to resolve the name using only the transport it has. If the
   machine is dual stacked, then the ``dual-stack-servers`` have no
   effect unless access to a transport has been disabled on the command
   line (e.g. ``named -4``).

.. _access_control:

Access Control
^^^^^^^^^^^^^^

Access to the server can be restricted based on the IP address of the
requesting system. See :ref:`address_match_lists`
for details on how to specify IP address lists.

``allow-notify``
   This ACL specifies which hosts may send NOTIFY messages to inform
   this server of changes to zones for which it is acting as a secondary
   server. This is only applicable for secondary zones (i.e., type
   ``secondary`` or ``slave``).

   If this option is set in ``view`` or ``options``, it is globally
   applied to all secondary zones. If set in the ``zone`` statement, the
   global value is overridden.

   If not specified, the default is to process NOTIFY messages only from
   the configured ``masters`` for the zone. ``allow-notify`` can be used
   to expand the list of permitted hosts, not to reduce it.

``allow-query``
   Specifies which hosts are allowed to ask ordinary DNS questions.
   ``allow-query`` may also be specified in the ``zone`` statement, in
   which case it overrides the ``options allow-query`` statement. If not
   specified, the default is to allow queries from all hosts.

   .. note:: ``allow-query-cache`` is now used to specify access to the cache.

``allow-query-on``
   Specifies which local addresses can accept ordinary DNS questions.
   This makes it possible, for instance, to allow queries on
   internal-facing interfaces but disallow them on external-facing ones,
   without necessarily knowing the internal network's addresses.

   Note that ``allow-query-on`` is only checked for queries that are
   permitted by ``allow-query``. A query must be allowed by both ACLs,
   or it will be refused.

   ``allow-query-on`` may also be specified in the ``zone`` statement,
   in which case it overrides the ``options allow-query-on`` statement.

   If not specified, the default is to allow queries on all addresses.

   .. note:: ``allow-query-cache`` is used to specify access to the cache.

``allow-query-cache``
   Specifies which hosts are allowed to get answers from the cache. If
   ``allow-query-cache`` is not set then ``allow-recursion`` is used if
   set, otherwise ``allow-query`` is used if set unless
   ``recursion no;`` is set in which case ``none;`` is used, otherwise
   the default (``localnets;`` ``localhost;``) is used.

``allow-query-cache-on``
   Specifies which local addresses can send answers from the cache. If
   ``allow-query-cache-on`` is not set, then ``allow-recursion-on`` is
   used if set. Otherwise, the default is to allow cache responses to be
   sent from any address. Note: Both ``allow-query-cache`` and
   ``allow-query-cache-on`` must be satisfied before a cache response
   can be sent; a client that is blocked by one cannot be allowed by the
   other.

``allow-recursion``
   Specifies which hosts are allowed to make recursive queries through
   this server. If ``allow-recursion`` is not set then
   ``allow-query-cache`` is used if set, otherwise ``allow-query`` is
   used if set, otherwise the default (``localnets;`` ``localhost;``) is
   used.

``allow-recursion-on``
   Specifies which local addresses can accept recursive queries. If
   ``allow-recursion-on`` is not set, then ``allow-query-cache-on`` is
   used if set; otherwise, the default is to allow recursive queries on
   all addresses: Any client permitted to send recursive queries can
   send them to any address on which ``named`` is listening. Note: Both
   ``allow-recursion`` and ``allow-recursion-on`` must be satisfied
   before recursion is allowed; a client that is blocked by one cannot
   be allowed by the other.

``allow-update``
   When set in the ``zone`` statement for a master zone, specifies which
   hosts are allowed to submit Dynamic DNS updates to that zone. The
   default is to deny updates from all hosts.

   Note that allowing updates based on the requestor's IP address is
   insecure; see :ref:`dynamic_update_security` for details.

   In general this option should only be set at the ``zone`` level.
   While a default value can be set at the ``options`` or ``view`` level
   and inherited by zones, this could lead to some zones unintentionally
   allowing updates.

``allow-update-forwarding``
   When set in the ``zone`` statement for a slave zone, specifies which
   hosts are allowed to submit Dynamic DNS updates and have them be
   forwarded to the master. The default is ``{ none; }``, which means
   that no update forwarding will be performed.

   To enable update forwarding, specify
   ``allow-update-forwarding { any; };``. in the ``zone`` statement.
   Specifying values other than ``{ none; }`` or ``{ any; }`` is usually
   counterproductive; the responsibility for update access control
   should rest with the master server, not the slave.

   Note that enabling the update forwarding feature on a slave server
   may expose master servers to attacks if they rely on insecure
   IP-address-based access control; see :ref:`dynamic_update_security` for more details.

   In general this option should only be set at the ``zone`` level.
   While a default value can be set at the ``options`` or ``view`` level
   and inherited by zones, this can lead to some zones unintentionally
   forwarding updates.

``allow-v6-synthesis``
   This option was introduced for the smooth transition from AAAA to A6
   and from "nibble labels" to binary labels. However, since both A6 and
   binary labels were then deprecated, this option was also deprecated.
   It is now ignored with some warning messages.

.. _allow-transfer-access:

``allow-transfer``
   Specifies which hosts are allowed to receive zone transfers from the
   server. ``allow-transfer`` may also be specified in the ``zone``
   statement, in which case it overrides the ``allow-transfer``
   statement set in ``options`` or ``view``. If not specified, the
   default is to allow transfers to all hosts.

``blackhole``
   Specifies a list of addresses that the server will not accept queries
   from or use to resolve a query. Queries from these addresses will not
   be responded to. The default is ``none``.

``keep-response-order``
   Specifies a list of addresses to which the server will send responses
   to TCP queries in the same order in which they were received. This
   disables the processing of TCP queries in parallel. The default is
   ``none``.

``no-case-compress``
   Specifies a list of addresses which require responses to use
   case-insensitive compression. This ACL can be used when ``named``
   needs to work with clients that do not comply with the requirement in
   :rfc:`1034` to use case-insensitive name comparisons when checking for
   matching domain names.

   If left undefined, the ACL defaults to ``none``: case-insensitive
   compression will be used for all clients. If the ACL is defined and
   matches a client, then case will be ignored when compressing domain
   names in DNS responses sent to that client.

   This can result in slightly smaller responses: if a response contains
   the names "example.com" and "example.COM", case-insensitive
   compression would treat the second one as a duplicate. It also
   ensures that the case of the query name exactly matches the case of
   the owner names of returned records, rather than matching the case of
   the records entered in the zone file. This allows responses to
   exactly match the query, which is required by some clients due to
   incorrect use of case-sensitive comparisons.

   Case-insensitive compression is *always* used in AXFR and IXFR
   responses, regardless of whether the client matches this ACL.

   There are circumstances in which ``named`` will not preserve the case
   of owner names of records: if a zone file defines records of
   different types with the same name, but the capitalization of the
   name is different (e.g., "www.example.com/A" and
   "WWW.EXAMPLE.COM/AAAA"), then all responses for that name will use
   the *first* version of the name that was used in the zone file. This
   limitation may be addressed in a future release. However, domain
   names specified in the rdata of resource records (i.e., records of
   type NS, MX, CNAME, etc) will always have their case preserved unless
   the client matches this ACL.

``resolver-query-timeout``
   The amount of time in milliseconds that the resolver will spend
   attempting to resolve a recursive query before failing. The default
   and minimum is ``10000`` and the maximum is ``30000``. Setting it to
   ``0`` will result in the default being used.

   This value was originally specified in seconds. Values less than or
   equal to 300 will be be treated as seconds and converted to
   milliseconds before applying the above limits.

Interfaces
^^^^^^^^^^

The interfaces and ports that the server will answer queries from may be
specified using the ``listen-on`` option. ``listen-on`` takes an
optional port and an ``address_match_list`` of IPv4 addresses. (IPv6
addresses are ignored, with a logged warning.) The server will listen on
all interfaces allowed by the address match list. If a port is not
specified, port 53 will be used.

Multiple ``listen-on`` statements are allowed. For example,

::

   listen-on { 5.6.7.8; };
   listen-on port 1234 { !1.2.3.4; 1.2/16; };

will enable the name server on port 53 for the IP address 5.6.7.8, and
on port 1234 of an address on the machine in net 1.2 that is not
1.2.3.4.

If no ``listen-on`` is specified, the server will listen on port 53 on
all IPv4 interfaces.

The ``listen-on-v6`` option is used to specify the interfaces and the
ports on which the server will listen for incoming queries sent using
IPv6. If not specified, the server will listen on port 53 on all IPv6
interfaces.

When

::

   { any; }

is specified as the ``address_match_list`` for the ``listen-on-v6``
option, the server does not bind a separate socket to each IPv6
interface address as it does for IPv4 if the operating system has enough
API support for IPv6 (specifically if it conforms to :rfc:`3493` and
:rfc:`3542`). Instead, it listens on the IPv6 wildcard address. If the system
only has incomplete API support for IPv6, however, the behavior is the
same as that for IPv4.

A list of particular IPv6 addresses can also be specified, in which case
the server listens on a separate socket for each specified address,
regardless of whether the desired API is supported by the system. IPv4
addresses specified in ``listen-on-v6`` will be ignored, with a logged
warning.

Multiple ``listen-on-v6`` options can be used. For example,

::

   listen-on-v6 { any; };
   listen-on-v6 port 1234 { !2001:db8::/32; any; };

will enable the name server on port 53 for any IPv6 addresses (with a
single wildcard socket), and on port 1234 of IPv6 addresses that is not
in the prefix 2001:db8::/32 (with separate sockets for each matched
address.)

To make the server not listen on any IPv6 address, use

::

   listen-on-v6 { none; };

.. _query_address:

Query Address
^^^^^^^^^^^^^

If the server doesn't know the answer to a question, it will query other
name servers. ``query-source`` specifies the address and port used for
such queries. For queries sent over IPv6, there is a separate
``query-source-v6`` option. If ``address`` is ``*`` (asterisk) or is
omitted, a wildcard IP address (``INADDR_ANY``) will be used.

If ``port`` is ``*`` or is omitted, a random port number from a
pre-configured range is picked up and will be used for each query. The
port range(s) is that specified in the ``use-v4-udp-ports`` (for IPv4)
and ``use-v6-udp-ports`` (for IPv6) options, excluding the ranges
specified in the ``avoid-v4-udp-ports`` and ``avoid-v6-udp-ports``
options, respectively.

The defaults of the ``query-source`` and ``query-source-v6`` options
are:

::

   query-source address * port *;
   query-source-v6 address * port *;

If ``use-v4-udp-ports`` or ``use-v6-udp-ports`` is unspecified,
``named`` will check if the operating system provides a programming
interface to retrieve the system's default range for ephemeral ports. If
such an interface is available, ``named`` will use the corresponding
system default range; otherwise, it will use its own defaults:

::

   use-v4-udp-ports { range 1024 65535; };
   use-v6-udp-ports { range 1024 65535; };

.. note:: Make sure the ranges be sufficiently large for security. A
   desirable size depends on various parameters, but we generally recommend
   it contain at least 16384 ports (14 bits of entropy). Note also that the
   system's default range when used may be too small for this purpose, and
   that the range may even be changed while ``named`` is running; the new
   range will automatically be applied when ``named`` is reloaded. It is
   encouraged to configure ``use-v4-udp-ports`` and ``use-v6-udp-ports``
   explicitly so that the ranges are sufficiently large and are reasonably
   independent from the ranges used by other applications.

.. note:: The operational configuration where ``named`` runs may prohibit
   the use of some ports. For example, UNIX systems will not allow
   ``named`` running without a root privilege to use ports less than 1024.
   If such ports are included in the specified (or detected) set of query
   ports, the corresponding query attempts will fail, resulting in
   resolution failures or delay. It is therefore important to configure the
   set of ports that can be safely used in the expected operational
   environment.

The defaults of the ``avoid-v4-udp-ports`` and ``avoid-v6-udp-ports``
options are:

::

   avoid-v4-udp-ports {};
   avoid-v6-udp-ports {};

.. note:: BIND 9.5.0 introduced the ``use-queryport-pool`` option to support
   a pool of such random ports, but this option is now obsolete because
   reusing the same ports in the pool may not be sufficiently secure. For
   the same reason, it is generally strongly discouraged to specify a
   particular port for the ``query-source`` or ``query-source-v6`` options;
   it implicitly disables the use of randomized port numbers.

``use-queryport-pool``
   This option is obsolete.

``queryport-pool-ports``
   This option is obsolete.

``queryport-pool-updateinterval``
   This option is obsolete.

   .. note:: The address specified in the ``query-source`` option is used for both
      UDP and TCP queries, but the port applies only to UDP queries. TCP
      queries always use a random unprivileged port.

   .. note:: Solaris 2.5.1 and earlier does not support setting the source address
      for TCP sockets.

   .. note:: See also ``transfer-source`` and ``notify-source``.

.. _zone_transfers:

Zone Transfers
^^^^^^^^^^^^^^

BIND has mechanisms in place to facilitate zone transfers and set limits
on the amount of load that transfers place on the system. The following
options apply to zone transfers.

``also-notify``
   Defines a global list of IP addresses of name servers that are also
   sent NOTIFY messages whenever a fresh copy of the zone is loaded, in
   addition to the servers listed in the zone's NS records. This helps
   to ensure that copies of the zones will quickly converge on stealth
   servers. Optionally, a port may be specified with each
   ``also-notify`` address to send the notify messages to a port other
   than the default of 53. An optional TSIG key can also be specified
   with each address to cause the notify messages to be signed; this can
   be useful when sending notifies to multiple views. In place of
   explicit addresses, one or more named ``masters`` lists can be used.

   If an ``also-notify`` list is given in a ``zone`` statement, it will
   override the ``options also-notify`` statement. When a
   ``zone notify`` statement is set to ``no``, the IP addresses in the
   global ``also-notify`` list will not be sent NOTIFY messages for that
   zone. The default is the empty list (no global notification list).

``max-transfer-time-in``
   Inbound zone transfers running longer than this many minutes will be
   terminated. The default is 120 minutes (2 hours). The maximum value
   is 28 days (40320 minutes).

``max-transfer-idle-in``
   Inbound zone transfers making no progress in this many minutes will
   be terminated. The default is 60 minutes (1 hour). The maximum value
   is 28 days (40320 minutes).

``max-transfer-time-out``
   Outbound zone transfers running longer than this many minutes will be
   terminated. The default is 120 minutes (2 hours). The maximum value
   is 28 days (40320 minutes).

``max-transfer-idle-out``
   Outbound zone transfers making no progress in this many minutes will
   be terminated. The default is 60 minutes (1 hour). The maximum value
   is 28 days (40320 minutes).

``notify-rate``
   The rate at which NOTIFY requests will be sent during normal zone
   maintenance operations. (NOTIFY requests due to initial zone loading
   are subject to a separate rate limit; see below.) The default is 20
   per second. The lowest possible rate is one per second; when set to
   zero, it will be silently raised to one.

``startup-notify-rate``
   The rate at which NOTIFY requests will be sent when the name server
   is first starting up, or when zones have been newly added to the
   nameserver. The default is 20 per second. The lowest possible rate is
   one per second; when set to zero, it will be silently raised to one.

``serial-query-rate``
   Slave servers will periodically query master servers to find out if
   zone serial numbers have changed. Each such query uses a minute
   amount of the slave server's network bandwidth. To limit the amount
   of bandwidth used, BIND 9 limits the rate at which queries are sent.
   The value of the ``serial-query-rate`` option, an integer, is the
   maximum number of queries sent per second. The default is 20 per
   second. The lowest possible rate is one per second; when set to zero,
   it will be silently raised to one.

``transfer-format``
   Zone transfers can be sent using two different formats,
   ``one-answer`` and ``many-answers``. The ``transfer-format`` option
   is used on the master server to determine which format it sends.
   ``one-answer`` uses one DNS message per resource record transferred.
   ``many-answers`` packs as many resource records as possible into a
   message. ``many-answers`` is more efficient, but is only supported by
   relatively new slave servers, such as BIND 9, BIND 8.x and BIND 4.9.5
   onwards. The ``many-answers`` format is also supported by recent
   Microsoft Windows nameservers. The default is ``many-answers``.
   ``transfer-format`` may be overridden on a per-server basis by using
   the ``server`` statement.

``transfer-message-size``
   This is an upper bound on the uncompressed size of DNS messages used
   in zone transfers over TCP. If a message grows larger than this size,
   additional messages will be used to complete the zone transfer.
   (Note, however, that this is a hint, not a hard limit; if a message
   contains a single resource record whose RDATA does not fit within the
   size limit, a larger message will be permitted so the record can be
   transferred.)

   Valid values are between 512 and 65535 octets, and any values outside
   that range will be adjusted to the nearest value within it. The
   default is ``20480``, which was selected to improve message
   compression: most DNS messages of this size will compress to less
   than 16536 bytes. Larger messages cannot be compressed as
   effectively, because 16536 is the largest permissible compression
   offset pointer in a DNS message.

   This option is mainly intended for server testing; there is rarely
   any benefit in setting a value other than the default.

``transfers-in``
   The maximum number of inbound zone transfers that can be running
   concurrently. The default value is ``10``. Increasing
   ``transfers-in`` may speed up the convergence of slave zones, but it
   also may increase the load on the local system.

``transfers-out``
   The maximum number of outbound zone transfers that can be running
   concurrently. Zone transfer requests in excess of the limit will be
   refused. The default value is ``10``.

``transfers-per-ns``
   The maximum number of inbound zone transfers that can be concurrently
   transferring from a given remote name server. The default value is
   ``2``. Increasing ``transfers-per-ns`` may speed up the convergence
   of slave zones, but it also may increase the load on the remote name
   server. ``transfers-per-ns`` may be overridden on a per-server basis
   by using the ``transfers`` phrase of the ``server`` statement.

``transfer-source``
   ``transfer-source`` determines which local address will be bound to
   IPv4 TCP connections used to fetch zones transferred inbound by the
   server. It also determines the source IPv4 address, and optionally
   the UDP port, used for the refresh queries and forwarded dynamic
   updates. If not set, it defaults to a system controlled value which
   will usually be the address of the interface "closest to" the remote
   end. This address must appear in the remote end's ``allow-transfer``
   option for the zone being transferred, if one is specified. This
   statement sets the ``transfer-source`` for all zones, but can be
   overridden on a per-view or per-zone basis by including a
   ``transfer-source`` statement within the ``view`` or ``zone`` block
   in the configuration file.

   .. note:: Solaris 2.5.1 and earlier does not support setting the source
      address for TCP sockets.

``transfer-source-v6``
   The same as ``transfer-source``, except zone transfers are performed
   using IPv6.

``alt-transfer-source``
   An alternate transfer source if the one listed in ``transfer-source``
   fails and ``use-alt-transfer-source`` is set.

   .. note:: If you do not wish the alternate transfer source to be used, you
      should set ``use-alt-transfer-source`` appropriately and you
      should not depend upon getting an answer back to the first refresh
      query.

``alt-transfer-source-v6``
   An alternate transfer source if the one listed in
   ``transfer-source-v6`` fails and ``use-alt-transfer-source`` is set.

``use-alt-transfer-source``
   Use the alternate transfer sources or not. If views are specified
   this defaults to ``no``, otherwise it defaults to ``yes``.

``notify-source``
   ``notify-source`` determines which local source address, and
   optionally UDP port, will be used to send NOTIFY messages. This
   address must appear in the slave server's ``masters`` zone clause or
   in an ``allow-notify`` clause. This statement sets the
   ``notify-source`` for all zones, but can be overridden on a per-zone
   or per-view basis by including a ``notify-source`` statement within
   the ``zone`` or ``view`` block in the configuration file.

   .. note:: Solaris 2.5.1 and earlier does not support setting the source
      address for TCP sockets.

``notify-source-v6``
   Like ``notify-source``, but applies to notify messages sent to IPv6
   addresses.

.. _port_lists:

UDP Port Lists
^^^^^^^^^^^^^^

``use-v4-udp-ports``, ``avoid-v4-udp-ports``, ``use-v6-udp-ports``, and
``avoid-v6-udp-ports`` specify a list of IPv4 and IPv6 UDP ports that
will be used or not used as source ports for UDP messages. See
:ref:`query_address` about how the available ports are
determined. For example, with the following configuration

::

   use-v6-udp-ports { range 32768 65535; };
   avoid-v6-udp-ports { 40000; range 50000 60000; };

UDP ports of IPv6 messages sent from ``named`` will be in one of the
following ranges: 32768 to 39999, 40001 to 49999, and 60001 to 65535.

``avoid-v4-udp-ports`` and ``avoid-v6-udp-ports`` can be used to prevent
``named`` from choosing as its random source port a port that is blocked
by your firewall or a port that is used by other applications; if a
query went out with a source port blocked by a firewall, the answer
would not get by the firewall and the name server would have to query
again. Note: the desired range can also be represented only with
``use-v4-udp-ports`` and ``use-v6-udp-ports``, and the ``avoid-``
options are redundant in that sense; they are provided for backward
compatibility and to possibly simplify the port specification.

.. _resource_limits:

Operating System Resource Limits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The server's usage of many system resources can be limited. Scaled
values are allowed when specifying resource limits. For example, ``1G``
can be used instead of ``1073741824`` to specify a limit of one
gigabyte. ``unlimited`` requests unlimited use, or the maximum available
amount. ``default`` uses the limit that was in force when the server was
started. See the description of ``size_spec`` in :ref:`configuration_file_elements`.

The following options set operating system resource limits for the name
server process. Some operating systems don't support some or any of the
limits. On such systems, a warning will be issued if the unsupported
limit is used.

``coresize``
   The maximum size of a core dump. The default is ``default``.

``datasize``
   The maximum amount of data memory the server may use. The default is
   ``default``. This is a hard limit on server memory usage. If the
   server attempts to allocate memory in excess of this limit, the
   allocation will fail, which may in turn leave the server unable to
   perform DNS service. Therefore, this option is rarely useful as a way
   of limiting the amount of memory used by the server, but it can be
   used to raise an operating system data size limit that is too small
   by default. If you wish to limit the amount of memory used by the
   server, use the ``max-cache-size`` and ``recursive-clients`` options
   instead.

``files``
   The maximum number of files the server may have open concurrently.
   The default is ``unlimited``.

``stacksize``
   The maximum amount of stack memory the server may use. The default is
   ``default``.

.. _server_resource_limits:

Server Resource Limits
^^^^^^^^^^^^^^^^^^^^^^

The following options set limits on the server's resource consumption
that are enforced internally by the server rather than the operating
system.

``max-journal-size``
   Sets a maximum size for each journal file (see :ref:`journal`),
   expressed in bytes or, if followed by an
   optional unit suffix ('k', 'm', or 'g'), in kilobytes, megabytes, or
   gigabytes. When the journal file approaches the specified size, some
   of the oldest transactions in the journal will be automatically
   removed. The largest permitted value is 2 gigabytes. Very small
   values are rounded up to 4096 bytes. You can specify ``unlimited``,
   which also means 2 gigabytes. If you set the limit to ``default`` or
   leave it unset, the journal is allowed to grow up to twice as large
   as the zone. (There is little benefit in storing larger journals.)

   This option may also be set on a per-zone basis.

``max-records``
   The maximum number of records permitted in a zone. The default is
   zero which means unlimited.

``recursive-clients``
   The maximum number ("hard quota") of simultaneous recursive lookups
   the server will perform on behalf of clients. The default is
   ``1000``. Because each recursing client uses a fair bit of memory (on
   the order of 20 kilobytes), the value of the ``recursive-clients``
   option may have to be decreased on hosts with limited memory.

   ``recursive-clients`` defines a "hard quota" limit for pending
   recursive clients: when more clients than this are pending, new
   incoming requests will not be accepted, and for each incoming request
   a previous pending request will also be dropped.

   A "soft quota" is also set. When this lower quota is exceeded,
   incoming requests are accepted, but for each one, a pending request
   will be dropped. If ``recursive-clients`` is greater than 1000, the
   soft quota is set to ``recursive-clients`` minus 100; otherwise it is
   set to 90% of ``recursive-clients``.

``tcp-clients``
   The maximum number of simultaneous client TCP connections that the
   server will accept. The default is ``150``.

.. _clients-per-query:

``clients-per-query``; \ ``max-clients-per-query``
   These set the initial value (minimum) and maximum number of recursive
   simultaneous clients for any given query (<qname,qtype,qclass>) that
   the server will accept before dropping additional clients. ``named``
   will attempt to self tune this value and changes will be logged. The
   default values are 10 and 100.

   This value should reflect how many queries come in for a given name
   in the time it takes to resolve that name. If the number of queries
   exceed this value, ``named`` will assume that it is dealing with a
   non-responsive zone and will drop additional queries. If it gets a
   response after dropping queries, it will raise the estimate. The
   estimate will then be lowered in 20 minutes if it has remained
   unchanged.

   If ``clients-per-query`` is set to zero, then there is no limit on
   the number of clients per query and no queries will be dropped.

   If ``max-clients-per-query`` is set to zero, then there is no upper
   bound other than imposed by ``recursive-clients``.

``fetches-per-zone``
   The maximum number of simultaneous iterative queries to any one
   domain that the server will permit before blocking new queries for
   data in or beneath that zone. This value should reflect how many
   fetches would normally be sent to any one zone in the time it would
   take to resolve them. It should be smaller than
   ``recursive-clients``.

   When many clients simultaneously query for the same name and type,
   the clients will all be attached to the same fetch, up to the
   ``max-clients-per-query`` limit, and only one iterative query will be
   sent. However, when clients are simultaneously querying for
   *different* names or types, multiple queries will be sent and
   ``max-clients-per-query`` is not effective as a limit.

   Optionally, this value may be followed by the keyword ``drop`` or
   ``fail``, indicating whether queries which exceed the fetch quota for
   a zone will be dropped with no response, or answered with SERVFAIL.
   The default is ``drop``.

   If ``fetches-per-zone`` is set to zero, then there is no limit on the
   number of fetches per query and no queries will be dropped. The
   default is zero.

   The current list of active fetches can be dumped by running
   ``rndc recursing``. The list includes the number of active fetches
   for each domain and the number of queries that have been passed or
   dropped as a result of the ``fetches-per-zone`` limit. (Note: these
   counters are not cumulative over time; whenever the number of active
   fetches for a domain drops to zero, the counter for that domain is
   deleted, and the next time a fetch is sent to that domain, it is
   recreated with the counters set to zero.)

``fetches-per-server``
   The maximum number of simultaneous iterative queries that the server
   will allow to be sent to a single upstream name server before
   blocking additional queries. This value should reflect how many
   fetches would normally be sent to any one server in the time it would
   take to resolve them. It should be smaller than
   ``recursive-clients``.

   Optionally, this value may be followed by the keyword ``drop`` or
   ``fail``, indicating whether queries will be dropped with no
   response, or answered with SERVFAIL, when all of the servers
   authoritative for a zone are found to have exceeded the per-server
   quota. The default is ``fail``.

   If ``fetches-per-server`` is set to zero, then there is no limit on
   the number of fetches per query and no queries will be dropped. The
   default is zero.

   The ``fetches-per-server`` quota is dynamically adjusted in response
   to detected congestion. As queries are sent to a server and are
   either answered or time out, an exponentially weighted moving average
   is calculated of the ratio of timeouts to responses. If the current
   average timeout ratio rises above a "high" threshold, then
   ``fetches-per-server`` is reduced for that server. If the timeout
   ratio drops below a "low" threshold, then ``fetches-per-server`` is
   increased. The ``fetch-quota-params`` options can be used to adjust
   the parameters for this calculation.

``fetch-quota-params``
   Sets the parameters to use for dynamic resizing of the
   ``fetches-per-server`` quota in response to detected congestion.

   The first argument is an integer value indicating how frequently to
   recalculate the moving average of the ratio of timeouts to responses
   for each server. The default is 100, meaning we recalculate the
   average ratio after every 100 queries have either been answered or
   timed out.

   The remaining three arguments represent the "low" threshold
   (defaulting to a timeout ratio of 0.1), the "high" threshold
   (defaulting to a timeout ratio of 0.3), and the discount rate for the
   moving average (defaulting to 0.7). A higher discount rate causes
   recent events to weigh more heavily when calculating the moving
   average; a lower discount rate causes past events to weigh more
   heavily, smoothing out short-term blips in the timeout ratio. These
   arguments are all fixed-point numbers with precision of 1/100: at
   most two places after the decimal point are significant.

``reserved-sockets``
   The number of file descriptors reserved for TCP, stdio, etc. This
   needs to be big enough to cover the number of interfaces ``named``
   listens on plus ``tcp-clients``, as well as to provide room for
   outgoing TCP queries and incoming zone transfers. The default is
   ``512``. The minimum value is ``128`` and the maximum value is
   ``128`` less than maxsockets (-S). This option may be removed in the
   future.

   This option has little effect on Windows.

``max-cache-size``
   The maximum amount of memory to use for the server's cache, in bytes
   or % of total physical memory. When the amount of data in the cache
   reaches this limit, the server will cause records to expire
   prematurely based on an LRU based strategy so that the limit is not
   exceeded. The keyword ``unlimited``, or the value 0, will place no
   limit on cache size; records will be purged from the cache only when
   their TTLs expire. Any positive values less than 2MB will be ignored
   and reset to 2MB. In a server with multiple views, the limit applies
   separately to the cache of each view. The default is ``90%``. On
   systems where detection of amount of physical memory is not supported
   values represented as % fall back to unlimited. Note that the
   detection of physical memory is done only once at startup, so
   ``named`` will not adjust the cache size if the amount of physical
   memory is changed during runtime.

``tcp-listen-queue``
   The listen queue depth. The default and minimum is 10. If the kernel
   supports the accept filter "dataready" this also controls how many
   TCP connections that will be queued in kernel space waiting for some
   data before being passed to accept. Nonzero values less than 10 will
   be silently raised. A value of 0 may also be used; on most platforms
   this sets the listen queue length to a system-defined default value.

``tcp-initial-timeout``
   The amount of time (in units of 100 milliseconds) the server waits on
   a new TCP connection for the first message from the client. The
   default is 300 (30 seconds), the minimum is 25 (2.5 seconds), and the
   maximum is 1200 (two minutes). Values above the maximum or below the
   minimum will be adjusted with a logged warning. (Note: This value
   must be greater than the expected round trip delay time; otherwise no
   client will ever have enough time to submit a message.) This value
   can be updated at runtime by using ``rndc tcp-timeouts``.

``tcp-idle-timeout``
   The amount of time (in units of 100 milliseconds) the server waits on
   an idle TCP connection before closing it when the client is not using
   the EDNS TCP keepalive option. The default is 300 (30 seconds), the
   maximum is 1200 (two minutes), and the minimum is 1 (one tenth of a
   second). Values above the maximum or below the minimum will be
   adjusted with a logged warning. See ``tcp-keepalive-timeout`` for
   clients using the EDNS TCP keepalive option. This value can be
   updated at runtime by using ``rndc tcp-timeouts``.

``tcp-keepalive-timeout``
   The amount of time (in units of 100 milliseconds) the server waits on
   an idle TCP connection before closing it when the client is using the
   EDNS TCP keepalive option. The default is 300 (30 seconds), the
   maximum is 65535 (about 1.8 hours), and the minimum is 1 (one tenth
   of a second). Values above the maximum or below the minimum will be
   adjusted with a logged warning. This value may be greater than
   ``tcp-idle-timeout``, because clients using the EDNS TCP keepalive
   option are expected to use TCP connections for more than one message.
   This value can be updated at runtime by using ``rndc tcp-timeouts``.

``tcp-advertised-timeout``
   The timeout value (in units of 100 milliseconds) the server will send
   in respones containing the EDNS TCP keepalive option. This informs a
   client of the amount of time it may keep the session open. The
   default is 300 (30 seconds), the maximum is 65535 (about 1.8 hours),
   and the minimum is 0, which signals that the clients must close TCP
   connections immediately. Ordinarily this should be set to the same
   value as ``tcp-keepalive-timeout``. This value can be updated at
   runtime by using ``rndc tcp-timeouts``.

.. _intervals:

Periodic Task Intervals
^^^^^^^^^^^^^^^^^^^^^^^

``cleaning-interval``
   This option is obsolete.

``heartbeat-interval``
   The server will perform zone maintenance tasks for all zones marked
   as ``dialup`` whenever this interval expires. The default is 60
   minutes. Reasonable values are up to 1 day (1440 minutes). The
   maximum value is 28 days (40320 minutes). If set to 0, no zone
   maintenance for these zones will occur.

``interface-interval``
   The server will scan the network interface list every ``interface-interval``
   minutes. The default is 60 minutes. The maximum value is 28 days (40320
   minutes). If set to 0, interface scanning will only occur the configuration
   file is loaded, or when ``automatic-interface-scan`` is enabled and supported
   by the operating system. After the scan, the server will begin listening for
   queries on any newly discovered interfaces (provided they are allowed by the
   ``listen-on`` configuration), and will stop listening on interfaces that have
   gone away. For convenience, TTL-style time unit suffixes may be used to
   specify the value. It also accepts ISO 8601 duration formats.

.. _the_sortlist_statement:

The ``sortlist`` Statement
^^^^^^^^^^^^^^^^^^^^^^^^^^

The response to a DNS query may consist of multiple resource records
(RRs) forming a resource record set (RRset). The name server will
normally return the RRs within the RRset in an indeterminate order (but
see the ``rrset-order`` statement in :ref:`rrset_ordering`). The client resolver code should
rearrange the RRs as appropriate, that is, using any addresses on the
local net in preference to other addresses. However, not all resolvers
can do this or are correctly configured. When a client is using a local
server, the sorting can be performed in the server, based on the
client's address. This only requires configuring the name servers, not
all the clients.

The ``sortlist`` statement (see below) takes an ``address_match_list`` and
interprets it in a special way. Each top level statement in the ``sortlist``
must itself be an explicit ``address_match_list`` with one or two elements. The
first element (which may be an IP address, an IP prefix, an ACL name or a nested
``address_match_list``) of each top level list is checked against the source
address of the query until a match is found. When the addresses in the first
element overlap, the first rule to match gets selected.

Once the source address of the query has been matched, if the top level
statement contains only one element, the actual primitive element that
matched the source address is used to select the address in the response
to move to the beginning of the response. If the statement is a list of
two elements, then the second element is interpreted as a topology
preference list. Each top level element is assigned a distance and the
address in the response with the minimum distance is moved to the
beginning of the response.

In the following example, any queries received from any of the addresses
of the host itself will get responses preferring addresses on any of the
locally connected networks. Next most preferred are addresses on the
192.168.1/24 network, and after that either the 192.168.2/24 or
192.168.3/24 network with no preference shown between these two
networks. Queries received from a host on the 192.168.1/24 network will
prefer other addresses on that network to the 192.168.2/24 and
192.168.3/24 networks. Queries received from a host on the 192.168.4/24
or the 192.168.5/24 network will only prefer other addresses on their
directly connected networks.

::

   sortlist {
       // IF the local host
       // THEN first fit on the following nets
       { localhost;
       { localnets;
           192.168.1/24;
           { 192.168.2/24; 192.168.3/24; }; }; };
       // IF on class C 192.168.1 THEN use .1, or .2 or .3
       { 192.168.1/24;
       { 192.168.1/24;
           { 192.168.2/24; 192.168.3/24; }; }; };
       // IF on class C 192.168.2 THEN use .2, or .1 or .3
       { 192.168.2/24;
       { 192.168.2/24;
           { 192.168.1/24; 192.168.3/24; }; }; };
       // IF on class C 192.168.3 THEN use .3, or .1 or .2
       { 192.168.3/24;
       { 192.168.3/24;
           { 192.168.1/24; 192.168.2/24; }; }; };
       // IF .4 or .5 THEN prefer that net
       { { 192.168.4/24; 192.168.5/24; };
       };
   };

The following example will give reasonable behavior for the local host
and hosts on directly connected networks. It is similar to the behavior
of the address sort in BIND 4.9.x. Responses sent to queries from the
local host will favor any of the directly connected networks. Responses
sent to queries from any other hosts on a directly connected network
will prefer addresses on that same network. Responses to other queries
will not be sorted.

::

   sortlist {
          { localhost; localnets; };
          { localnets; };
   };

.. _rrset_ordering:

RRset Ordering
^^^^^^^^^^^^^^

When multiple records are returned in an answer it may be useful to
configure the order of the records placed into the response. The
``rrset-order`` statement permits configuration of the ordering of the
records in a multiple-record response. See also the ``sortlist``
statement, :ref:`the_sortlist_statement`.

An ``order_spec`` is defined as follows:

[class *class_name*] [type *type_name*] [name "*domain_name*"] order *ordering*

If no class is specified, the default is ``ANY``. If no type is
specified, the default is ``ANY``. If no name is specified, the default
is "``*``" (asterisk).

The legal values for ``ordering`` are:

``fixed``
    Records are returned in the order they are defined in the zone file. This option is only available if BIND is configured with "--enable-fixed-rrset" at compile time.

``random``
    Records are returned in some random order.

``cyclic``
    Records are returned in a cyclic round-robin order, rotating by one record per query. If BIND is configured with "--enable-fixed-rrset" at compile time, then the initial ordering of the RRset will match the one specified in the zone file; otherwise the initial ordering is indeterminate.

``none``
    Records are returned in whatever order they were retrieved from the database. This order is indeterminate, but will be consistent as long as the database is not modified. When no ordering is specified, this is the default.

For example:

::

   rrset-order {
      class IN type A name "host.example.com" order random;
      order cyclic;
   };

will cause any responses for type A records in class IN that have
"``host.example.com``" as a suffix, to always be returned in random
order. All other records are returned in cyclic order.

If multiple ``rrset-order`` statements appear, they are not combined —
the last one applies.

By default, records are returned in ``random`` order.

.. note::

   In this release of BIND 9, the ``rrset-order`` statement does not
   support "fixed" ordering by default. Fixed ordering can be enabled at
   compile time by specifying "--enable-fixed-rrset" on the "configure"
   command line.

.. _tuning:

Tuning
^^^^^^

``lame-ttl``
   Sets the number of seconds to cache a lame server indication. 0
   disables caching. (This is **NOT** recommended.) The default is
   ``600`` (10 minutes) and the maximum value is ``1800`` (30 minutes).

``servfail-ttl``
   Sets the number of seconds to cache a SERVFAIL response due to DNSSEC
   validation failure or other general server failure. If set to ``0``,
   SERVFAIL caching is disabled. The SERVFAIL cache is not consulted if
   a query has the CD (Checking Disabled) bit set; this allows a query
   that failed due to DNSSEC validation to be retried without waiting
   for the SERVFAIL TTL to expire.

   The maximum value is ``30`` seconds; any higher value will be
   silently reduced. The default is ``1`` second.

``min-ncache-ttl``
   To reduce network traffic and increase performance, the server stores
   negative answers. ``min-ncache-ttl`` is used to set a minimum
   retention time for these answers in the server in seconds. For
   convenience, TTL-style time unit suffixes may be used to specify the
   value. It also accepts ISO 8601 duration formats.

   The default ``min-ncache-ttl`` is ``0`` seconds.  ``min-ncache-ttl`` cannot
   exceed 90 seconds and will be truncated to 90 seconds if set to a greater
   value.

``min-cache-ttl``
   Sets the minimum time for which the server will cache ordinary (positive)
   answers in seconds. For convenience, TTL-style time unit suffixes may be used
   to specify the value. It also accepts ISO 8601 duration formats.

   The default ``min-cache-ttl`` is ``0`` seconds. ``min-cache-ttl`` cannot
   exceed 90 seconds and will be truncated to 90 seconds if set to a greater
   value.

``max-ncache-ttl``
   To reduce network traffic and increase performance, the server stores
   negative answers. ``max-ncache-ttl`` is used to set a maximum retention time
   for these answers in the server in seconds.  For convenience, TTL-style time
   unit suffixes may be used to specify the value.  It also accepts ISO 8601
   duration formats.

   The default ``max-ncache-ttl`` is 10800 seconds (3 hours). ``max-ncache-ttl``
   cannot exceed 7 days and will be silently truncated to 7 days if set to a
   greater value.

``max-cache-ttl``
   Sets the maximum time for which the server will cache ordinary (positive)
   answers in seconds. For convenience, TTL-style time unit suffixes may be used
   to specify the value. It also accepts ISO 8601 duration formats.

   The default ``max-cache-ttl`` is 604800 (one week). A value of zero may cause
   all queries to return SERVFAIL, because of lost caches of intermediate RRsets
   (such as NS and glue AAAA/A records) in the resolution process.

``max-stale-ttl``
   If stale answers are enabled, ``max-stale-ttl`` sets the maximum time
   for which the server will retain records past their normal expiry to
   return them as stale records when the servers for those records are
   not reachable. The default is 1 week. The minimum allowed is 1
   second; a value of 0 will be updated silently to 1 second.

   For stale answers to be returned, they must be enabled, either in the
   configuration file using ``stale-answer-enable`` or via
   ``rndc serve-stale on``.

``resolver-nonbackoff-tries``
   Specifies how many retries occur before exponential backoff kicks in. The
   default is ``3``.

``resolver-retry-interval``
   The base retry interval in milliseconds. The default is ``800``.

``sig-validity-interval``
   Specifies the number of days into the future when DNSSEC signatures
   automatically generated as a result of dynamic updates
   (:ref:`dynamic_update`) will expire. There is an optional second
   field which specifies how long before expiry that the signatures will
   be regenerated. If not specified, the signatures will be regenerated
   at 1/4 of base interval. The second field is specified in days if the
   base interval is greater than 7 days otherwise it is specified in
   hours. The default base interval is ``30`` days giving a re-signing
   interval of 7 1/2 days. The maximum values are 10 years (3660 days).

   The signature inception time is unconditionally set to one hour
   before the current time to allow for a limited amount of clock skew.

   The ``sig-validity-interval`` can be overridden for DNSKEY records by
   setting ``dnskey-sig-validity``.

   The ``sig-validity-interval`` should be, at least, several multiples
   of the SOA expire interval to allow for reasonable interaction
   between the various timer and expiry dates.

``dnskey-sig-validity``
   Specifies the number of days into the future when DNSSEC signatures
   that are automatically generated for DNSKEY RRsets as a result of
   dynamic updates (:ref:`dynamic_update`) will expire.
   If set to a non-zero value, this overrides the value set by
   ``sig-validity-interval``. The default is zero, meaning
   ``sig-validity-interval`` is used. The maximum value is 3660 days (10
   years), and higher values will be rejected.

``sig-signing-nodes``
   Specify the maximum number of nodes to be examined in each quantum
   when signing a zone with a new DNSKEY. The default is ``100``.

``sig-signing-signatures``
   Specify a threshold number of signatures that will terminate
   processing a quantum when signing a zone with a new DNSKEY. The
   default is ``10``.

``sig-signing-type``
   Specify a private RDATA type to be used when generating signing state
   records. The default is ``65534``.

   It is expected that this parameter may be removed in a future version
   once there is a standard type.

   Signing state records are used to internally by ``named`` to track
   the current state of a zone-signing process, i.e., whether it is
   still active or has been completed. The records can be inspected
   using the command ``rndc signing -list zone``. Once ``named`` has
   finished signing a zone with a particular key, the signing state
   record associated with that key can be removed from the zone by
   running ``rndc signing -clear keyid/algorithm zone``. To clear all of
   the completed signing state records for a zone, use
   ``rndc signing -clear all zone``.

``min-refresh-time``; \ ``max-refresh-time``; \ ``min-retry-time``; \ ``max-retry-time``
   These options control the server's behavior on refreshing a zone
   (querying for SOA changes) or retrying failed transfers. Usually the
   SOA values for the zone are used, up to a hard-coded maximum expiry
   of 24 weeks. However, these values are set by the master, giving
   slave server administrators little control over their contents.

   These options allow the administrator to set a minimum and maximum
   refresh and retry time in seconds per-zone, per-view, or globally.
   These options are valid for slave and stub zones, and clamp the SOA
   refresh and retry times to the specified values.

   The following defaults apply. ``min-refresh-time`` 300 seconds,
   ``max-refresh-time`` 2419200 seconds (4 weeks), ``min-retry-time``
   500 seconds, and ``max-retry-time`` 1209600 seconds (2 weeks).

``edns-udp-size``
   Sets the maximum advertised EDNS UDP buffer size in bytes, to control
   the size of packets received from authoritative servers in response
   to recursive queries. Valid values are 512 to 4096 (values outside
   this range will be silently adjusted to the nearest value within it).
   The default value is 4096.

   The usual reason for setting ``edns-udp-size`` to a non-default value
   is to get UDP answers to pass through broken firewalls that block
   fragmented packets and/or block UDP DNS packets that are greater than
   512 bytes.

   When ``named`` first queries a remote server, it will advertise a UDP
   buffer size of 512, as this has the greatest chance of success on the
   first try.

   If the initial query is successful with EDNS advertising a buffer size of
   512, then ``named`` will advertise progressively larger buffer sizes on
   successive queries, until responses begin timing out or ``edns-udp-size`` is
   reached.

   The default buffer sizes used by ``named`` are 512, 1232, 1432, and
   4096, but never exceeding ``edns-udp-size``. (The values 1232 and
   1432 are chosen to allow for an IPv4/IPv6 encapsulated UDP message to
   be sent without fragmentation at the minimum MTU sizes for Ethernet
   and IPv6 networks.)

``max-udp-size``
   Sets the maximum EDNS UDP message size ``named`` will send in bytes.
   Valid values are 512 to 4096 (values outside this range will be
   silently adjusted to the nearest value within it). The default value
   is 4096.

   This value applies to responses sent by a server; to set the
   advertised buffer size in queries, see ``edns-udp-size``.

   The usual reason for setting ``max-udp-size`` to a non-default value
   is to get UDP answers to pass through broken firewalls that block
   fragmented packets and/or block UDP packets that are greater than 512
   bytes. This is independent of the advertised receive buffer
   (``edns-udp-size``).

   Setting this to a low value will encourage additional TCP traffic to
   the nameserver.

``masterfile-format``
   Specifies the file format of zone files (see :ref:`zonefile_format`).
   The default value is ``text``, which
   is the standard textual representation, except for slave zones, in
   which the default value is ``raw``. Files in other formats than
   ``text`` are typically expected to be generated by the
   ``named-compilezone`` tool, or dumped by ``named``.

   Note that when a zone file in a different format than ``text`` is
   loaded, ``named`` may omit some of the checks which would be
   performed for a file in the ``text`` format. In particular,
   ``check-names`` checks do not apply for the ``raw`` format. This
   means a zone file in the ``raw`` format must be generated with the
   same check level as that specified in the ``named`` configuration
   file. Also, ``map`` format files are loaded directly into memory via
   memory mapping, with only minimal checking.

   This statement sets the ``masterfile-format`` for all zones, but can
   be overridden on a per-zone or per-view basis by including a
   ``masterfile-format`` statement within the ``zone`` or ``view`` block
   in the configuration file.

``masterfile-style``
   Specifies the formatting of zone files during dump when the
   ``masterfile-format`` is ``text``. (This option is ignored with any
   other ``masterfile-format``.)

   When set to ``relative``, records are printed in a multi-line format
   with owner names expressed relative to a shared origin. When set to
   ``full``, records are printed in a single-line format with absolute
   owner names. The ``full`` format is most suitable when a zone file
   needs to be processed automatically by a script. The ``relative``
   format is more human-readable, and is thus suitable when a zone is to
   be edited by hand. The default is ``relative``.

``max-recursion-depth``
   Sets the maximum number of levels of recursion that are permitted at
   any one time while servicing a recursive query. Resolving a name may
   require looking up a name server address, which in turn requires
   resolving another name, etc; if the number of indirections exceeds
   this value, the recursive query is terminated and returns SERVFAIL.
   The default is 7.

``max-recursion-queries``
   Sets the maximum number of iterative queries that may be sent while
   servicing a recursive query. If more queries are sent, the recursive
   query is terminated and returns SERVFAIL. Queries to look up top
   level domains such as "com" and "net" and the DNS root zone are
   exempt from this limitation. The default is 75.

``notify-delay``
   The delay, in seconds, between sending sets of notify messages for a
   zone. The default is five (5) seconds.

   The overall rate that NOTIFY messages are sent for all zones is
   controlled by ``serial-query-rate``.

``max-rsa-exponent-size``
   The maximum RSA exponent size, in bits, that will be accepted when
   validating. Valid values are 35 to 4096 bits. The default zero (0) is
   also accepted and is equivalent to 4096.

``prefetch``
   When a query is received for cached data which is to expire shortly,
   ``named`` can refresh the data from the authoritative server
   immediately, ensuring that the cache always has an answer available.

   The ``prefetch`` specifies the "trigger" TTL value at which prefetch
   of the current query will take place: when a cache record with a
   lower TTL value is encountered during query processing, it will be
   refreshed. Valid trigger TTL values are 1 to 10 seconds. Values
   larger than 10 seconds will be silently reduced to 10. Setting a
   trigger TTL to zero (0) causes prefetch to be disabled. The default
   trigger TTL is ``2``.

   An optional second argument specifies the "eligibility" TTL: the
   smallest *original* TTL value that will be accepted for a record to
   be eligible for prefetching. The eligibility TTL must be at least six
   seconds longer than the trigger TTL; if it isn't, ``named`` will
   silently adjust it upward. The default eligibility TTL is ``9``.

``v6-bias``
   When determining the next nameserver to try preference IPv6
   nameservers by this many milliseconds. The default is ``50``
   milliseconds.

.. _builtin:

Built-in server information zones
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The server provides some helpful diagnostic information through a number
of built-in zones under the pseudo-top-level-domain ``bind`` in the
``CHAOS`` class. These zones are part of a built-in view
(see :ref:`view_statement_grammar`) of class ``CHAOS`` which is
separate from the default view of class ``IN``. Most global
configuration options (``allow-query``, etc) will apply to this view,
but some are locally overridden: ``notify``, ``recursion`` and
``allow-new-zones`` are always set to ``no``, and ``rate-limit`` is set
to allow three responses per second.

If you need to disable these zones, use the options below, or hide the
built-in ``CHAOS`` view by defining an explicit view of class ``CHAOS``
that matches all clients.

``version``
   The version the server should report via a query of the name
   ``version.bind`` with type ``TXT``, class ``CHAOS``. The default is
   the real version number of this server. Specifying ``version none``
   disables processing of the queries.

   Setting ``version`` to any value (including ``none``) will also disable
   queries for ``authors.bind TXT CH``.

``hostname``
   The hostname the server should report via a query of the name
   ``hostname.bind`` with type ``TXT``, class ``CHAOS``. This defaults
   to the hostname of the machine hosting the name server as found by
   the gethostname() function. The primary purpose of such queries is to
   identify which of a group of anycast servers is actually answering
   your queries. Specifying ``hostname none;`` disables processing of
   the queries.

``server-id``
   The ID the server should report when receiving a Name Server
   Identifier (NSID) query, or a query of the name ``ID.SERVER`` with
   type ``TXT``, class ``CHAOS``. The primary purpose of such queries is
   to identify which of a group of anycast servers is actually answering
   your queries. Specifying ``server-id none;`` disables processing of
   the queries. Specifying ``server-id hostname;`` will cause ``named``
   to use the hostname as found by the gethostname() function. The
   default ``server-id`` is ``none``.

.. _empty:

Built-in Empty Zones
^^^^^^^^^^^^^^^^^^^^

The ``named`` server has some built-in empty zones (SOA and NS records
only). These are for zones that should normally be answered locally and
which queries should not be sent to the Internet's root servers. The
official servers which cover these namespaces return NXDOMAIN responses
to these queries. In particular, these cover the reverse namespaces for
addresses from :rfc:`1918`, :rfc:`4193`, :rfc:`5737` and :rfc:`6598`. They also
include the reverse namespace for IPv6 local address (locally assigned),
IPv6 link local addresses, the IPv6 loopback address and the IPv6
unknown address.

The server will attempt to determine if a built-in zone already exists
or is active (covered by a forward-only forwarding declaration) and will
not create an empty zone in that case.

The current list of empty zones is:

-  10.IN-ADDR.ARPA
-  16.172.IN-ADDR.ARPA
-  17.172.IN-ADDR.ARPA
-  18.172.IN-ADDR.ARPA
-  19.172.IN-ADDR.ARPA
-  20.172.IN-ADDR.ARPA
-  21.172.IN-ADDR.ARPA
-  22.172.IN-ADDR.ARPA
-  23.172.IN-ADDR.ARPA
-  24.172.IN-ADDR.ARPA
-  25.172.IN-ADDR.ARPA
-  26.172.IN-ADDR.ARPA
-  27.172.IN-ADDR.ARPA
-  28.172.IN-ADDR.ARPA
-  29.172.IN-ADDR.ARPA
-  30.172.IN-ADDR.ARPA
-  31.172.IN-ADDR.ARPA
-  168.192.IN-ADDR.ARPA
-  64.100.IN-ADDR.ARPA
-  65.100.IN-ADDR.ARPA
-  66.100.IN-ADDR.ARPA
-  67.100.IN-ADDR.ARPA
-  68.100.IN-ADDR.ARPA
-  69.100.IN-ADDR.ARPA
-  70.100.IN-ADDR.ARPA
-  71.100.IN-ADDR.ARPA
-  72.100.IN-ADDR.ARPA
-  73.100.IN-ADDR.ARPA
-  74.100.IN-ADDR.ARPA
-  75.100.IN-ADDR.ARPA
-  76.100.IN-ADDR.ARPA
-  77.100.IN-ADDR.ARPA
-  78.100.IN-ADDR.ARPA
-  79.100.IN-ADDR.ARPA
-  80.100.IN-ADDR.ARPA
-  81.100.IN-ADDR.ARPA
-  82.100.IN-ADDR.ARPA
-  83.100.IN-ADDR.ARPA
-  84.100.IN-ADDR.ARPA
-  85.100.IN-ADDR.ARPA
-  86.100.IN-ADDR.ARPA
-  87.100.IN-ADDR.ARPA
-  88.100.IN-ADDR.ARPA
-  89.100.IN-ADDR.ARPA
-  90.100.IN-ADDR.ARPA
-  91.100.IN-ADDR.ARPA
-  92.100.IN-ADDR.ARPA
-  93.100.IN-ADDR.ARPA
-  94.100.IN-ADDR.ARPA
-  95.100.IN-ADDR.ARPA
-  96.100.IN-ADDR.ARPA
-  97.100.IN-ADDR.ARPA
-  98.100.IN-ADDR.ARPA
-  99.100.IN-ADDR.ARPA
-  100.100.IN-ADDR.ARPA
-  101.100.IN-ADDR.ARPA
-  102.100.IN-ADDR.ARPA
-  103.100.IN-ADDR.ARPA
-  104.100.IN-ADDR.ARPA
-  105.100.IN-ADDR.ARPA
-  106.100.IN-ADDR.ARPA
-  107.100.IN-ADDR.ARPA
-  108.100.IN-ADDR.ARPA
-  109.100.IN-ADDR.ARPA
-  110.100.IN-ADDR.ARPA
-  111.100.IN-ADDR.ARPA
-  112.100.IN-ADDR.ARPA
-  113.100.IN-ADDR.ARPA
-  114.100.IN-ADDR.ARPA
-  115.100.IN-ADDR.ARPA
-  116.100.IN-ADDR.ARPA
-  117.100.IN-ADDR.ARPA
-  118.100.IN-ADDR.ARPA
-  119.100.IN-ADDR.ARPA
-  120.100.IN-ADDR.ARPA
-  121.100.IN-ADDR.ARPA
-  122.100.IN-ADDR.ARPA
-  123.100.IN-ADDR.ARPA
-  124.100.IN-ADDR.ARPA
-  125.100.IN-ADDR.ARPA
-  126.100.IN-ADDR.ARPA
-  127.100.IN-ADDR.ARPA
-  0.IN-ADDR.ARPA
-  127.IN-ADDR.ARPA
-  254.169.IN-ADDR.ARPA
-  2.0.192.IN-ADDR.ARPA
-  100.51.198.IN-ADDR.ARPA
-  113.0.203.IN-ADDR.ARPA
-  255.255.255.255.IN-ADDR.ARPA
-  0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA
-  1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA
-  8.B.D.0.1.0.0.2.IP6.ARPA
-  D.F.IP6.ARPA
-  8.E.F.IP6.ARPA
-  9.E.F.IP6.ARPA
-  A.E.F.IP6.ARPA
-  B.E.F.IP6.ARPA
-  EMPTY.AS112.ARPA
-  HOME.ARPA

Empty zones are settable at the view level and only apply to views of
class IN. Disabled empty zones are only inherited from options if there
are no disabled empty zones specified at the view level. To override the
options list of disabled zones, you can disable the root zone at the
view level, for example:

::

           disable-empty-zone ".";

If you are using the address ranges covered here, you should already
have reverse zones covering the addresses you use. In practice this
appears to not be the case with many queries being made to the
infrastructure servers for names in these spaces. So many in fact that
sacrificial servers were needed to be deployed to channel the query load
away from the infrastructure servers.

.. note::

   The real parent servers for these zones should disable all empty zone
   under the parent zone they serve. For the real root servers, this is
   all built-in empty zones. This will enable them to return referrals
   to deeper in the tree.

``empty-server``
   Specify what server name will appear in the returned SOA record for
   empty zones. If none is specified, then the zone's name will be used.

``empty-contact``
   Specify what contact name will appear in the returned SOA record for
   empty zones. If none is specified, then "." will be used.

``empty-zones-enable``
   Enable or disable all empty zones. By default, they are enabled.

``disable-empty-zone``
   Disable individual empty zones. By default, none are disabled. This
   option can be specified multiple times.

.. _content_filtering:

Content Filtering
^^^^^^^^^^^^^^^^^

BIND 9 provides the ability to filter out DNS responses from external
DNS servers containing certain types of data in the answer section.
Specifically, it can reject address (A or AAAA) records if the
corresponding IPv4 or IPv6 addresses match the given
``address_match_list`` of the ``deny-answer-addresses`` option. It can
also reject CNAME or DNAME records if the "alias" name (i.e., the CNAME
alias or the substituted query name due to DNAME) matches the given
``namelist`` of the ``deny-answer-aliases`` option, where "match" means
the alias name is a subdomain of one of the ``name_list`` elements. If
the optional ``namelist`` is specified with ``except-from``, records
whose query name matches the list will be accepted regardless of the
filter setting. Likewise, if the alias name is a subdomain of the
corresponding zone, the ``deny-answer-aliases`` filter will not apply;
for example, even if "example.com" is specified for
``deny-answer-aliases``,

::

   www.example.com. CNAME xxx.example.com.

returned by an "example.com" server will be accepted.

In the ``address_match_list`` of the ``deny-answer-addresses`` option,
only ``ip_addr`` and ``ip_prefix`` are meaningful; any ``key_id`` will
be silently ignored.

If a response message is rejected due to the filtering, the entire
message is discarded without being cached, and a SERVFAIL error will be
returned to the client.

This filtering is intended to prevent "DNS rebinding attacks," in which
an attacker, in response to a query for a domain name the attacker
controls, returns an IP address within your own network or an alias name
within your own domain. A naive web browser or script could then serve
as an unintended proxy, allowing the attacker to get access to an
internal node of your local network that couldn't be externally accessed
otherwise. See the paper available at
http://portal.acm.org/citation.cfm?id=1315245.1315298 for more details
about the attacks.

For example, if you own a domain named "example.net" and your internal
network uses an IPv4 prefix 192.0.2.0/24, you might specify the
following rules:

::

   deny-answer-addresses { 192.0.2.0/24; } except-from { "example.net"; };
   deny-answer-aliases { "example.net"; };

If an external attacker lets a web browser in your local network look up
an IPv4 address of "attacker.example.com", the attacker's DNS server
would return a response like this:

::

   attacker.example.com. A 192.0.2.1

in the answer section. Since the rdata of this record (the IPv4 address)
matches the specified prefix 192.0.2.0/24, this response will be
ignored.

On the other hand, if the browser looks up a legitimate internal web
server "www.example.net" and the following response is returned to the
BIND 9 server

::

   www.example.net. A 192.0.2.2

it will be accepted since the owner name "www.example.net" matches the
``except-from`` element, "example.net".

Note that this is not really an attack on the DNS per se. In fact, there
is nothing wrong for an "external" name to be mapped to your "internal"
IP address or domain name from the DNS point of view. It might actually
be provided for a legitimate purpose, such as for debugging. As long as
the mapping is provided by the correct owner, it is not possible or does
not make sense to detect whether the intent of the mapping is legitimate
or not within the DNS. The "rebinding" attack must primarily be
protected at the application that uses the DNS. For a large site,
however, it may be difficult to protect all possible applications at
once. This filtering feature is provided only to help such an
operational environment; it is generally discouraged to turn it on
unless you are very sure you have no other choice and the attack is a
real threat for your applications.

Care should be particularly taken if you want to use this option for
addresses within 127.0.0.0/8. These addresses are obviously "internal",
but many applications conventionally rely on a DNS mapping from some
name to such an address. Filtering out DNS records containing this
address spuriously can break such applications.

.. _rpz:

Response Policy Zone (RPZ) Rewriting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

BIND 9 includes a limited mechanism to modify DNS responses for requests
analogous to email anti-spam DNS blacklists. Responses can be changed to
deny the existence of domains (NXDOMAIN), deny the existence of IP
addresses for domains (NODATA), or contain other IP addresses or data.

Response policy zones are named in the ``response-policy`` option for
the view or among the global options if there is no response-policy
option for the view. Response policy zones are ordinary DNS zones
containing RRsets that can be queried normally if allowed. It is usually
best to restrict those queries with something like
``allow-query { localhost; };``. Note that zones using
``masterfile-format map`` cannot be used as policy zones.

A ``response-policy`` option can support multiple policy zones. To
maximize performance, a radix tree is used to quickly identify response
policy zones containing triggers that match the current query. This
imposes an upper limit of 64 on the number of policy zones in a single
``response-policy`` option; more than that is a configuration error.

Rules encoded in response policy zones are processed after
:ref:`access_control`.  All queries from clients which are not permitted access
to the resolver will be answered with a status code of REFUSED, regardless of
configured RPZ rules.

Five policy triggers can be encoded in RPZ records.

``RPZ-CLIENT-IP``
   IP records are triggered by the IP address of the DNS client. Client
   IP address triggers are encoded in records that have owner names that
   are subdomains of ``rpz-client-ip`` relativized to the policy zone
   origin name and encode an address or address block. IPv4 addresses
   are represented as ``prefixlength.B4.B3.B2.B1.rpz-client-ip``. The
   IPv4 prefix length must be between 1 and 32. All four bytes, B4, B3,
   B2, and B1, must be present. B4 is the decimal value of the least
   significant byte of the IPv4 address as in IN-ADDR.ARPA.

   IPv6 addresses are encoded in a format similar to the standard IPv6
   text representation,
   ``prefixlength.W8.W7.W6.W5.W4.W3.W2.W1.rpz-client-ip``. Each of
   W8,...,W1 is a one to four digit hexadecimal number representing 16
   bits of the IPv6 address as in the standard text representation of
   IPv6 addresses, but reversed as in IP6.ARPA. (Note that this
   representation of IPv6 address is different from IP6.ARPA where each
   hex digit occupies a label.) All 8 words must be present except when
   one set of consecutive zero words is replaced with ``.zz.`` analogous
   to double colons (::) in standard IPv6 text encodings. The IPv6
   prefix length must be between 1 and 128.

``QNAME``
   QNAME policy records are triggered by query names of requests and
   targets of CNAME records resolved to generate the response. The owner
   name of a QNAME policy record is the query name relativized to the
   policy zone.

``RPZ-IP``
   IP triggers are IP addresses in an A or AAAA record in the ANSWER
   section of a response. They are encoded like client-IP triggers
   except as subdomains of ``rpz-ip``.

``RPZ-NSDNAME``
   NSDNAME triggers match names of authoritative servers for the query name, a
   parent of the query name, a CNAME for query name, or a parent of a CNAME.
   They are encoded as subdomains of <command>rpz-nsdname</command> relativized
   to the RPZ origin name.  NSIP triggers match IP addresses in A and AAAA
   RRsets for domains that can be checked against NSDNAME policy records.  The
   ``nsdname-enable`` phrase turns NSDNAME triggers off or on for a single
   policy zone or all zones.

   If authoritative nameservers for the query name are not yet known, ``named``
   will recursively look up the authoritative servers for the query name before
   applying an RPZ-NSDNAME rule.  This can cause a processing delay. To speed up
   processing at the cost of precision, the ``nsdname-wait-recurse`` option can
   be used: when set to ``no``, RPZ-NSDNAME rules will only be applied when
   authoritative servers for the query name have already been looked up and
   cached.  If authoritative servers for the query name are not in the cache,
   then the RPZ-NSDNAME rule will be ignored, but the authoritative servers for
   the query name will be looked up in the background, and the rule will be
   applied to subsequent queries. The default is ``yes``,
   meaning RPZ-NSDNAME rules should always be applied even if authoritative
   servers for the query name need to be looked up first.

``RPZ-NSIP``
   NSIP triggers match the IP addresses of authoritative servers. They
   are enncoded like IP triggers, except as subdomains of ``rpz-nsip``.
   NSDNAME and NSIP triggers are checked only for names with at least
   ``min-ns-dots`` dots. The default value of ``min-ns-dots`` is 1, to
   exclude top level domains. The ``nsip-enable`` phrase turns NSIP
   triggers off or on for a single policy zone or all zones.

   If a name server's IP address is not yet known, ``named`` will
   recursively look up the IP address before applying an RPZ-NSIP rule.
   This can cause a processing delay. To speed up processing at the cost
   of precision, the ``nsip-wait-recurse`` option can be used: when set
   to ``no``, RPZ-NSIP rules will only be applied when a name servers's
   IP address has already been looked up and cached. If a server's IP
   address is not in the cache, then the RPZ-NSIP rule will be ignored,
   but the address will be looked up in the background, and the rule
   will be applied to subsequent queries. The default is ``yes``,
   meaning RPZ-NSIP rules should always be applied even if an address
   needs to be looked up first.

The query response is checked against all response policy zones, so two
or more policy records can be triggered by a response. Because DNS
responses are rewritten according to at most one policy record, a single
record encoding an action (other than ``DISABLED`` actions) must be
chosen. Triggers or the records that encode them are chosen for the
rewriting in the following order:

1. Choose the triggered record in the zone that appears first in the
   response-policy
   option.
2. Prefer CLIENT-IP to QNAME to IP to NSDNAME to NSIP triggers in a
   single zone.
3. Among NSDNAME triggers, prefer the trigger that matches the smallest
   name under the DNSSEC ordering.
4. Among IP or NSIP triggers, prefer the trigger with the longest
   prefix.
5. Among triggers with the same prefix length, prefer the IP or NSIP
   trigger that matches the smallest IP address.

When the processing of a response is restarted to resolve DNAME or CNAME
records and a policy record set has not been triggered, all response
policy zones are again consulted for the DNAME or CNAME names and
addresses.

RPZ record sets are any types of DNS record except DNAME or DNSSEC that
encode actions or responses to individual queries. Any of the policies
can be used with any of the triggers. For example, while the
``TCP-only`` policy is commonly used with ``client-IP`` triggers, it can
be used with any type of trigger to force the use of TCP for responses
with owner names in a zone.

``PASSTHRU``
   The whitelist policy is specified by a CNAME whose target is
   ``rpz-passthru``. It causes the response to not be rewritten and is
   most often used to "poke holes" in policies for CIDR blocks.

``DROP``
   The blacklist policy is specified by a CNAME whose target is
   ``rpz-drop``. It causes the response to be discarded. Nothing is sent
   to the DNS client.

``TCP-Only``
   The "slip" policy is specified by a CNAME whose target is
   ``rpz-tcp-only``. It changes UDP responses to short, truncated DNS
   responses that require the DNS client to try again with TCP. It is
   used to mitigate distributed DNS reflection attacks.

``NXDOMAIN``
   The domain undefined response is encoded by a CNAME whose target is
   the root domain (.)

``NODATA``
   The empty set of resource records is specified by CNAME whose target
   is the wildcard top-level domain (``*.``). It rewrites the response to
   NODATA or ANCOUNT=0.

``Local Data``
   A set of ordinary DNS records can be used to answer queries. Queries
   for record types not the set are answered with NODATA.

   A special form of local data is a CNAME whose target is a wildcard
   such as \*.example.com. It is used as if were an ordinary CNAME after
   the asterisk (\*) has been replaced with the query name. The purpose
   for this special form is query logging in the walled garden's
   authority DNS server.

All of the actions specified in all of the individual records in a
policy zone can be overridden with a ``policy`` clause in the
``response-policy`` option. An organization using a policy zone provided
by another organization might use this mechanism to redirect domains to
its own walled garden.

``GIVEN``
   The placeholder policy says "do not override but perform the action
   specified in the zone."

``DISABLED``
   The testing override policy causes policy zone records to do nothing
   but log what they would have done if the policy zone were not
   disabled. The response to the DNS query will be written (or not)
   according to any triggered policy records that are not disabled.
   Disabled policy zones should appear first, because they will often
   not be logged if a higher precedence trigger is found first.

``PASSTHRU``; \ ``DROP``; \ ``TCP-Only``; \ ``NXDOMAIN``; \ ``NODATA``
   override with the corresponding per-record policy.

``CNAME domain``
   causes all RPZ policy records to act as if they were "cname domain"
   records.

By default, the actions encoded in a response policy zone are applied
only to queries that ask for recursion (RD=1). That default can be
changed for a single policy zone or all response policy zones in a view
with a ``recursive-only no`` clause. This feature is useful for serving
the same zone files both inside and outside an :rfc:`1918` cloud and using
RPZ to delete answers that would otherwise contain :rfc:`1918` values on
the externally visible name server or view.

Also by default, RPZ actions are applied only to DNS requests that
either do not request DNSSEC metadata (DO=0) or when no DNSSEC records
are available for request name in the original zone (not the response
policy zone). This default can be changed for all response policy zones
in a view with a ``break-dnssec yes`` clause. In that case, RPZ actions
are applied regardless of DNSSEC. The name of the clause option reflects
the fact that results rewritten by RPZ actions cannot verify.

No DNS records are needed for a QNAME or Client-IP trigger. The name or
IP address itself is sufficient, so in principle the query name need not
be recursively resolved. However, not resolving the requested name can
leak the fact that response policy rewriting is in use and that the name
is listed in a policy zone to operators of servers for listed names. To
prevent that information leak, by default any recursion needed for a
request is done before any policy triggers are considered. Because
listed domains often have slow authoritative servers, this behavior can
cost significant time. The ``qname-wait-recurse yes`` option overrides
the default and enables that behavior when recursion cannot change a
non-error response. The option does not affect QNAME or client-IP
triggers in policy zones listed after other zones containing IP, NSIP
and NSDNAME triggers, because those may depend on the A, AAAA, and NS
records that would be found during recursive resolution. It also does
not affect DNSSEC requests (DO=1) unless ``break-dnssec yes`` is in use,
because the response would depend on whether or not RRSIG records were
found during resolution. Using this option can cause error responses
such as SERVFAIL to appear to be rewritten, since no recursion is being
done to discover problems at the authoritative server.

The ``dnsrps-enable yes`` option turns on the DNS Rsponse Policy Service
(DNSRPS) interface, if it has been compiled in to ``named`` using
``configure --enable-dnsrps``.

The ``dnsrps-options`` block provides additional RPZ configuration
settings, which are passed through to the DNSRPS provider library.
Multiple DNSRPS settings in an ``dnsrps-options`` string should be
separated with semi-colons. The DNSRPS provider, librpz, is passed a
configuration string consisting of the ``dnsrps-options`` text,
concatenated with settings derived from the ``response-policy``
statement.

Note: The ``dnsrps-options`` text should only include configuration
settings that are specific to the DNSRPS provider. For example, the
DNSRPS provider from Farsight Security takes options such as
``dnsrpzd-conf``, ``dnsrpzd-sock``, and ``dnzrpzd-args`` (for details of
these options, see the ``librpz`` documentation). Other RPZ
configuration settings could be included in ``dnsrps-options`` as well,
but if ``named`` were switched back to traditional RPZ by setting
``dnsrps-enable`` to "no", those options would be ignored.

The TTL of a record modified by RPZ policies is set from the TTL of the
relevant record in policy zone. It is then limited to a maximum value.
The ``max-policy-ttl`` clause changes the maximum seconds from its
default of 5. For convenience, TTL-style time unit suffixes may be used
to specify the value. It also accepts ISO 8601 duration formats.

For example, you might use this option statement

::

       response-policy { zone "badlist"; };

and this zone statement

::

       zone "badlist" {type master; file "master/badlist"; allow-query {none;}; };

with this zone file

::

   $TTL 1H
   @                       SOA LOCALHOST. named-mgr.example.com (1 1h 15m 30d 2h)
               NS  LOCALHOST.

   ; QNAME policy records.  There are no periods (.) after the owner names.
   nxdomain.domain.com     CNAME   .               ; NXDOMAIN policy
   *.nxdomain.domain.com   CNAME   .               ; NXDOMAIN policy
   nodata.domain.com       CNAME   *.              ; NODATA policy
   *.nodata.domain.com     CNAME   *.              ; NODATA policy
   bad.domain.com          A       10.0.0.1        ; redirect to a walled garden
               AAAA    2001:2::1
   bzone.domain.com        CNAME   garden.example.com.

   ; do not rewrite (PASSTHRU) OK.DOMAIN.COM
   ok.domain.com           CNAME   rpz-passthru.

   ; redirect x.bzone.domain.com to x.bzone.domain.com.garden.example.com
   *.bzone.domain.com      CNAME   *.garden.example.com.

   ; IP policy records that rewrite all responses containing A records in 127/8
   ;       except 127.0.0.1
   8.0.0.0.127.rpz-ip      CNAME   .
   32.1.0.0.127.rpz-ip     CNAME   rpz-passthru.

   ; NSDNAME and NSIP policy records
   ns.domain.com.rpz-nsdname   CNAME   .
   48.zz.2.2001.rpz-nsip       CNAME   .

   ; blacklist and whitelist some DNS clients
   112.zz.2001.rpz-client-ip    CNAME   rpz-drop.
   8.0.0.0.127.rpz-client-ip    CNAME   rpz-drop.

   ; force some DNS clients and responses in the example.com zone to TCP
   16.0.0.1.10.rpz-client-ip   CNAME   rpz-tcp-only.
   example.com                 CNAME   rpz-tcp-only.
   *.example.com               CNAME   rpz-tcp-only.

RPZ can affect server performance. Each configured response policy zone
requires the server to perform one to four additional database lookups
before a query can be answered. For example, a DNS server with four
policy zones, each with all four kinds of response triggers, QNAME, IP,
NSIP, and NSDNAME, requires a total of 17 times as many database lookups
as a similar DNS server with no response policy zones. A BIND9 server
with adequate memory and one response policy zone with QNAME and IP
triggers might achieve a maximum queries-per-second rate about 20%
lower. A server with four response policy zones with QNAME and IP
triggers might have a maximum QPS rate about 50% lower.

Responses rewritten by RPZ are counted in the ``RPZRewrites``
statistics.

The ``log`` clause can be used to optionally turn off rewrite logging
for a particular response policy zone. By default, all rewrites are
logged.

The ``add-soa`` option controls whether the RPZ's SOA record is added to
the additional section for traceback of changes from this zone or not.
This can be set at the individual policy zone level or at the
response-policy level. The default is ``yes``.

Updates to RPZ zones are processed asynchronously; if there is more than
one update pending they are bundled together. If an update to a RPZ zone
(for example, via IXFR) happens less than ``min-update-interval``
seconds after the most recent update, then the changes will not be
carried out until this interval has elapsed. The default is ``60``
seconds. For convenience, TTL-style time unit suffixes may be used to
specify the value. It also accepts ISO 8601 duration formats.

.. _rrl:

Response Rate Limiting
^^^^^^^^^^^^^^^^^^^^^^

Excessive almost identical UDP *responses* can be controlled by
configuring a ``rate-limit`` clause in an ``options`` or ``view``
statement. This mechanism keeps authoritative BIND 9 from being used in
amplifying reflection denial of service (DoS) attacks. Short truncated
(TC=1) responses can be sent to provide rate-limited responses to
legitimate clients within a range of forged, attacked IP addresses.
Legitimate clients react to dropped or truncated response by retrying
with UDP or with TCP respectively.

This mechanism is intended for authoritative DNS servers. It can be used
on recursive servers but can slow applications such as SMTP servers
(mail receivers) and HTTP clients (web browsers) that repeatedly request
the same domains. When possible, closing "open" recursive servers is
better.

Response rate limiting uses a "credit" or "token bucket" scheme. Each
combination of identical response and client has a conceptual account
that earns a specified number of credits every second. A prospective
response debits its account by one. Responses are dropped or truncated
while the account is negative. Responses are tracked within a rolling
window of time which defaults to 15 seconds, but can be configured with
the ``window`` option to any value from 1 to 3600 seconds (1 hour). The
account cannot become more positive than the per-second limit or more
negative than ``window`` times the per-second limit. When the specified
number of credits for a class of responses is set to 0, those responses
are not rate limited.

The notions of "identical response" and "DNS client" for rate limiting
are not simplistic. All responses to an address block are counted as if
to a single client. The prefix lengths of addresses blocks are specified
with ``ipv4-prefix-length`` (default 24) and ``ipv6-prefix-length``
(default 56).

All non-empty responses for a valid domain name (qname) and record type
(qtype) are identical and have a limit specified with
``responses-per-second`` (default 0 or no limit). All empty (NODATA)
responses for a valid domain, regardless of query type, are identical.
Responses in the NODATA class are limited by ``nodata-per-second``
(default ``responses-per-second``). Requests for any and all undefined
subdomains of a given valid domain result in NXDOMAIN errors, and are
identical regardless of query type. They are limited by
``nxdomains-per-second`` (default ``responses-per-second``). This
controls some attacks using random names, but can be relaxed or turned
off (set to 0) on servers that expect many legitimate NXDOMAIN
responses, such as from anti-spam blacklists. Referrals or delegations
to the server of a given domain are identical and are limited by
``referrals-per-second`` (default ``responses-per-second``).

Responses generated from local wildcards are counted and limited as if
they were for the parent domain name. This controls flooding using
random.wild.example.com.

All requests that result in DNS errors other than NXDOMAIN, such as
SERVFAIL and FORMERR, are identical regardless of requested name (qname)
or record type (qtype). This controls attacks using invalid requests or
distant, broken authoritative servers. By default the limit on errors is
the same as the ``responses-per-second`` value, but it can be set
separately with ``errors-per-second``.

Many attacks using DNS involve UDP requests with forged source
addresses. Rate limiting prevents the use of BIND 9 to flood a network
with responses to requests with forged source addresses, but could let a
third party block responses to legitimate requests. There is a mechanism
that can answer some legitimate requests from a client whose address is
being forged in a flood. Setting ``slip`` to 2 (its default) causes
every other UDP request to be answered with a small truncated (TC=1)
response. The small size and reduced frequency, and so lack of
amplification, of "slipped" responses make them unattractive for
reflection DoS attacks. ``slip`` must be between 0 and 10. A value of 0
does not "slip": no truncated responses are sent due to rate limiting,
all responses are dropped. A value of 1 causes every response to slip;
values between 2 and 10 cause every n'th response to slip. Some error
responses including REFUSED and SERVFAIL cannot be replaced with
truncated responses and are instead leaked at the ``slip`` rate.

(NOTE: Dropped responses from an authoritative server may reduce the
difficulty of a third party successfully forging a response to a
recursive resolver. The best security against forged responses is for
authoritative operators to sign their zones using DNSSEC and for
resolver operators to validate the responses. When this is not an
option, operators who are more concerned with response integrity than
with flood mitigation may consider setting ``slip`` to 1, causing all
rate-limited responses to be truncated rather than dropped. This reduces
the effectiveness of rate-limiting against reflection attacks.)

When the approximate query per second rate exceeds the ``qps-scale``
value, then the ``responses-per-second``, ``errors-per-second``,
``nxdomains-per-second`` and ``all-per-second`` values are reduced by
the ratio of the current rate to the ``qps-scale`` value. This feature
can tighten defenses during attacks. For example, with
``qps-scale 250; responses-per-second 20;`` and a total query rate of
1000 queries/second for all queries from all DNS clients including via
TCP, then the effective responses/second limit changes to (250/1000)*20
or 5. Responses sent via TCP are not limited but are counted to compute
the query per second rate.

Communities of DNS clients can be given their own parameters or no rate
limiting by putting ``rate-limit`` statements in ``view`` statements
instead of the global ``option`` statement. A ``rate-limit`` statement
in a view replaces, rather than supplementing, a ``rate-limit``
statement among the main options. DNS clients within a view can be
exempted from rate limits with the ``exempt-clients`` clause.

UDP responses of all kinds can be limited with the ``all-per-second``
phrase. This rate limiting is unlike the rate limiting provided by
``responses-per-second``, ``errors-per-second``, and
``nxdomains-per-second`` on a DNS server which are often invisible to
the victim of a DNS reflection attack. Unless the forged requests of the
attack are the same as the legitimate requests of the victim, the
victim's requests are not affected. Responses affected by an
``all-per-second`` limit are always dropped; the ``slip`` value has no
effect. An ``all-per-second`` limit should be at least 4 times as large
as the other limits, because single DNS clients often send bursts of
legitimate requests. For example, the receipt of a single mail message
can prompt requests from an SMTP server for NS, PTR, A, and AAAA records
as the incoming SMTP/TCP/IP connection is considered. The SMTP server
can need additional NS, A, AAAA, MX, TXT, and SPF records as it
considers the STMP ``Mail From`` command. Web browsers often repeatedly
resolve the same names that are repeated in HTML <IMG> tags in a page.
``all-per-second`` is similar to the rate limiting offered by firewalls
but often inferior. Attacks that justify ignoring the contents of DNS
responses are likely to be attacks on the DNS server itself. They
usually should be discarded before the DNS server spends resources make
TCP connections or parsing DNS requests, but that rate limiting must be
done before the DNS server sees the requests.

The maximum size of the table used to track requests and rate limit
responses is set with ``max-table-size``. Each entry in the table is
between 40 and 80 bytes. The table needs approximately as many entries
as the number of requests received per second. The default is 20,000. To
reduce the cold start of growing the table, ``min-table-size`` (default
500) can set the minimum table size. Enable ``rate-limit`` category
logging to monitor expansions of the table and inform choices for the
initial and maximum table size.

Use ``log-only yes`` to test rate limiting parameters without actually
dropping any requests.

Responses dropped by rate limits are included in the ``RateDropped`` and
``QryDropped`` statistics. Responses that truncated by rate limits are
included in ``RateSlipped`` and ``RespTruncated``.

Named supports NXDOMAIN redirection via two methods:

-  Redirect zone :ref:`zone_statement_grammar`
-  Redirect namespace

With both methods when named gets a NXDOMAIN response it examines a
separate namespace to see if the NXDOMAIN response should be replaced
with an alternative response.

With a redirect zone (``zone "." { type redirect; };``), the data used
to replace the NXDOMAIN is held in a single zone which is not part of
the normal namespace. All the redirect information is contained in the
zone; there are no delegations.

With a redirect namespace (``option { nxdomain-redirect <suffix> };``)
the data used to replace the NXDOMAIN is part of the normal namespace
and is looked up by appending the specified suffix to the original
query name. This roughly doubles the cache required to process
NXDOMAIN responses as you have the original NXDOMAIN response and the
replacement data or a NXDOMAIN indicating that there is no
replacement.

If both a redirect zone and a redirect namespace are configured, the
redirect zone is tried first.

.. _server_statement_grammar:

``server`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/server.grammar.rst

.. _server_statement_definition_and_usage:

``server`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``server`` statement defines characteristics to be associated with a
remote name server. If a prefix length is specified, then a range of
servers is covered. Only the most specific server clause applies
regardless of the order in ``named.conf``.

The ``server`` statement can occur at the top level of the configuration
file or inside a ``view`` statement. If a ``view`` statement contains
one or more ``server`` statements, only those apply to the view and any
top-level ones are ignored. If a view contains no ``server`` statements,
any top-level ``server`` statements are used as defaults.

If you discover that a remote server is giving out bad data, marking it
as bogus will prevent further queries to it. The default value of
``bogus`` is ``no``.

The ``provide-ixfr`` clause determines whether the local server, acting
as master, will respond with an incremental zone transfer when the given
remote server, a slave, requests it. If set to ``yes``, incremental
transfer will be provided whenever possible. If set to ``no``, all
transfers to the remote server will be non-incremental. If not set, the
value of the ``provide-ixfr`` option in the view or global options block
is used as a default.

The ``request-ixfr`` clause determines whether the local server, acting
as a slave, will request incremental zone transfers from the given
remote server, a master. If not set, the value of the ``request-ixfr``
option in the view or global options block is used as a default. It may
also be set in the zone block and, if set there, it will override the
global or view setting for that zone.

IXFR requests to servers that do not support IXFR will automatically
fall back to AXFR. Therefore, there is no need to manually list which
servers support IXFR and which ones do not; the global default of
``yes`` should always work. The purpose of the ``provide-ixfr`` and
``request-ixfr`` clauses is to make it possible to disable the use of
IXFR even when both master and slave claim to support it, for example if
one of the servers is buggy and crashes or corrupts data when IXFR is
used.

The ``request-expire`` clause determines whether the local server, when
acting as a slave, will request the EDNS EXPIRE value. The EDNS EXPIRE
value indicates the remaining time before the zone data will expire and
need to be be refreshed. This is used when a secondary server transfers
a zone from another secondary server; when transferring from the
primary, the expiration timer is set from the EXPIRE field of the SOA
record instead. The default is ``yes``.

The ``edns`` clause determines whether the local server will attempt to
use EDNS when communicating with the remote server. The default is
``yes``.

The ``edns-udp-size`` option sets the EDNS UDP size that is advertised
by ``named`` when querying the remote server. Valid values are 512 to
4096 bytes (values outside this range will be silently adjusted to the
nearest value within it). This option is useful when you wish to
advertise a different value to this server than the value you advertise
globally, for example, when there is a firewall at the remote site that
is blocking large replies. (Note: Currently, this sets a single UDP size
for all packets sent to the server; ``named`` will not deviate from this
value. This differs from the behavior of ``edns-udp-size`` in
``options`` or ``view`` statements, where it specifies a maximum value.
The ``server`` statement behavior may be brought into conformance with
the ``options/view`` behavior in future releases.)

The ``edns-version`` option sets the maximum EDNS VERSION that will be
sent to the server(s) by the resolver. The actual EDNS version sent is
still subject to normal EDNS version negotiation rules (see :rfc:`6891`),
the maximum EDNS version supported by the server, and any other
heuristics that indicate that a lower version should be sent. This
option is intended to be used when a remote server reacts badly to a
given EDNS version or higher; it should be set to the highest version
the remote server is known to support. Valid values are 0 to 255; higher
values will be silently adjusted. This option will not be needed until
higher EDNS versions than 0 are in use.

The ``max-udp-size`` option sets the maximum EDNS UDP message size
``named`` will send. Valid values are 512 to 4096 bytes (values outside
this range will be silently adjusted). This option is useful when you
know that there is a firewall that is blocking large replies from
``named``.

The ``padding`` option adds EDNS Padding options to outgoing messages,
increasing the packet size to a multiple of the specified block size.
Valid block sizes range from 0 (the default, which disables the use of
EDNS Padding) to 512 bytes. Larger values will be reduced to 512, with a
logged warning. Note: This option is not currently compatible with no
TSIG or SIG(0), as the EDNS OPT record containing the padding would have
to be added to the packet after it had already been signed.

The ``tcp-only`` option sets the transport protocol to TCP. The default
is to use the UDP transport and to fallback on TCP only when a truncated
response is received.

The ``tcp-keepalive`` option adds EDNS TCP keepalive to messages sent
over TCP. Note currently idle timeouts in responses are ignored.

The server supports two zone transfer methods. The first,
``one-answer``, uses one DNS message per resource record transferred.
``many-answers`` packs as many resource records as possible into a
message. ``many-answers`` is more efficient, but is only known to be
understood by BIND 9, BIND 8.x, and patched versions of BIND 4.9.5. You
can specify which method to use for a server with the
``transfer-format`` option. If ``transfer-format`` is not specified, the
``transfer-format`` specified by the ``options`` statement will be used.

``transfers`` is used to limit the number of concurrent inbound zone
transfers from the specified server. If no ``transfers`` clause is
specified, the limit is set according to the ``transfers-per-ns``
option.

The ``keys`` clause identifies a ``key_id`` defined by the ``key``
statement, to be used for transaction security (:ref:`tsig`)
when talking to the remote server. When a request is sent to the remote
server, a request signature will be generated using the key specified
here and appended to the message. A request originating from the remote
server is not required to be signed by this key.

Only a single key per server is currently supported.

The ``transfer-source`` and ``transfer-source-v6`` clauses specify the
IPv4 and IPv6 source address to be used for zone transfer with the
remote server, respectively. For an IPv4 remote server, only
``transfer-source`` can be specified. Similarly, for an IPv6 remote
server, only ``transfer-source-v6`` can be specified. For more details,
see the description of ``transfer-source`` and ``transfer-source-v6`` in
:ref:`zone_transfers`.

The ``notify-source`` and ``notify-source-v6`` clauses specify the IPv4
and IPv6 source address to be used for notify messages sent to remote
servers, respectively. For an IPv4 remote server, only ``notify-source``
can be specified. Similarly, for an IPv6 remote server, only
``notify-source-v6`` can be specified.

The ``query-source`` and ``query-source-v6`` clauses specify the IPv4
and IPv6 source address to be used for queries sent to remote servers,
respectively. For an IPv4 remote server, only ``query-source`` can be
specified. Similarly, for an IPv6 remote server, only
``query-source-v6`` can be specified.

The ``request-nsid`` clause determines whether the local server will add
a NSID EDNS option to requests sent to the server. This overrides
``request-nsid`` set at the view or option level.

The ``send-cookie`` clause determines whether the local server will add
a COOKIE EDNS option to requests sent to the server. This overrides
``send-cookie`` set at the view or option level. The ``named`` server
may determine that COOKIE is not supported by the remote server and not
add a COOKIE EDNS option to requests.

.. _statschannels:

``statistics-channels`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/statistics-channels.grammar.rst

.. _statistics_channels:

``statistics-channels`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``statistics-channels`` statement declares communication channels to
be used by system administrators to get access to statistics information
of the name server.

This statement intends to be flexible to support multiple communication
protocols in the future, but currently only HTTP access is supported. It
requires that BIND 9 be compiled with libxml2 and/or json-c (also known
as libjson0); the ``statistics-channels`` statement is still accepted
even if it is built without the library, but any HTTP access will fail
with an error.

An ``inet`` control channel is a TCP socket listening at the specified
``ip_port`` on the specified ``ip_addr``, which can be an IPv4 or IPv6
address. An ``ip_addr`` of ``*`` (asterisk) is interpreted as the IPv4
wildcard address; connections will be accepted on any of the system's
IPv4 addresses. To listen on the IPv6 wildcard address, use an
``ip_addr`` of ``::``.

If no port is specified, port 80 is used for HTTP channels. The asterisk
"``*``" cannot be used for ``ip_port``.

The attempt of opening a statistics channel is restricted by the
optional ``allow`` clause. Connections to the statistics channel are
permitted based on the ``address_match_list``. If no ``allow`` clause is
present, ``named`` accepts connection attempts from any address; since
the statistics may contain sensitive internal information, it is highly
recommended to restrict the source of connection requests appropriately.

If no ``statistics-channels`` statement is present, ``named`` will not
open any communication channels.

The statistics are available in various formats and views depending on
the URI used to access them. For example, if the statistics channel is
configured to listen on 127.0.0.1 port 8888, then the statistics are
accessible in XML format at http://127.0.0.1:8888/ or
http://127.0.0.1:8888/xml. A CSS file is included which can format the
XML statistics into tables when viewed with a stylesheet-capable
browser, and into charts and graphs using the Google Charts API when
using a javascript-capable browser.

Broken-out subsets of the statistics can be viewed at
http://127.0.0.1:8888/xml/v3/status (server uptime and last
reconfiguration time), http://127.0.0.1:8888/xml/v3/server (server and
resolver statistics), http://127.0.0.1:8888/xml/v3/zones (zone
statistics), http://127.0.0.1:8888/xml/v3/net (network status and socket
statistics), http://127.0.0.1:8888/xml/v3/mem (memory manager
statistics), http://127.0.0.1:8888/xml/v3/tasks (task manager
statistics), and http://127.0.0.1:8888/xml/v3/traffic (traffic sizes).

The full set of statistics can also be read in JSON format at
http://127.0.0.1:8888/json, with the broken-out subsets at
http://127.0.0.1:8888/json/v1/status (server uptime and last
reconfiguration time), http://127.0.0.1:8888/json/v1/server (server and
resolver statistics), http://127.0.0.1:8888/json/v1/zones (zone
statistics), http://127.0.0.1:8888/json/v1/net (network status and
socket statistics), http://127.0.0.1:8888/json/v1/mem (memory manager
statistics), http://127.0.0.1:8888/json/v1/tasks (task manager
statistics), and http://127.0.0.1:8888/json/v1/traffic (traffic sizes).

.. _trust_anchors:

``trust-anchors`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/trust-anchors.grammar.rst

.. _trust-anchors:

``dnssec-keys`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``trust-anchors`` statement defines DNSSEC trust anchors. DNSSEC is
described in :ref:`DNSSEC`.

A trust anchor is defined when the public key or public key digest for a non-authoritative
zone is known, but cannot be securely obtained through DNS, either
because it is the DNS root zone or because its parent zone is unsigned.
Once a key or digest has been configured as a trust anchor, it is treated as if it
had been validated and proven secure.

The resolver attempts DNSSEC validation on all DNS data in subdomains of
configured trust anchors. (Validation below specified names can be
temporarily disabled by using ``rndc nta``, or permanently disabled with
the ``validate-except`` option).

All keys listed in ``trust-anchors``, and their corresponding zones, are
deemed to exist regardless of what parent zones say. Only keys
configured as trust anchors are used to validate the DNSKEY RRset for
the corresponding name. The parent's DS RRset will not be used.

``trust-anchors`` may be set at the top level of ``named.conf`` or within
a view. If it is set in both places, the configurations are additive:
keys defined at the top level are inherited by all views, but keys
defined in a view are only used within that view.

The ``trust-anchors`` statement can contain
multiple trust anchor entries, each consisting of a
domain name, followed by an "anchor type" keyword indicating
the trust anchor's format, followed by the key or digest data.

If the anchor type is ``static-key`` or
``initial-key``, then it is followed with the
key's flags, protocol, algorithm, and the Base64 representation
of the public key data. This is identical to the text
representation of a DNSKEY record.  Spaces, tabs, newlines and
carriage returns are ignored in the key data, so the
configuration may be split up into multiple lines.

If the anchor type is ``static-ds`` or
``initial-ds``, then it is followed with the
key tag, algorithm, digest type, and the hexadecimal
representation of the key digest. This is identical to the
text representation of a DS record.  Spaces, tabs, newlines
and carriage returns are ignored.

Trust anchors configured with the
``static-key`` or ``static-ds``
anchor types are immutable, while keys configured with
``initial-key`` or ``initial-ds``
can be kept up
to date automatically, without intervention from the resolver operator.
(``static-key`` keys are identical to keys configured using the
deprecated ``trusted-keys`` statement.)

Suppose, for example, that a zone's key-signing key was compromised, and
the zone owner had to revoke and replace the key. A resolver which had
the original key
configured using ``static-key`` or
``static-ds`` would be unable to validate
this zone any longer; it would reply with a SERVFAIL response
code.  This would continue until the resolver operator had
updated the ``trust-anchors`` statement with
the new key.

If, however, the trust anchor had been configured
``initial-key`` or ``initial-ds``
instead, then the zone owner could add a "stand-by" key to
their zone in advance.  ``named`` would store
the stand-by key, and when the original key was revoked,
``named`` would be able to transition smoothly
to the new key.  It would also recognize that the old key had
been revoked, and cease using that key to validate answers,
minimizing the damage that the compromised key could do.
This is the process used to keep the ICANN root DNSSEC key
up to date.

Whereas ``static-key`` and
``static-ds`` trust anchors continue
to be trusted until they are removed from
``named.conf``, an
``initial-key`` or ``initial-ds``
is only trusted <emphasis>once</emphasis>: for as long as it
takes to load the managed key database and start the
:rfc:`5011` key maintenance process.

It is not possible to mix static with initial trust anchors
for the same domain name.

The first time ``named`` runs with an
``initial-key`` or ``initial-ds``
configured in <filename>named.conf</filename>, it fetches the
DNSKEY RRset directly from the zone apex,
and validates it
using the trust anchor specified in ``trust-anchors``.
If the DNSKEY RRset is validly signed by a key matching
the trust anchor, then it is used as the basis for a new
managed keys database.

From that point on, whenever ``named`` runs, it sees the ``initial-key`` or ``initial-ds``
listed in ``trust-anchors``, checks to make sure :rfc:`5011` key maintenance
has already been initialized for the specified domain, and if so, it
simply moves on. The key specified in the ``trust-anchors`` statement is
not used to validate answers; it is superseded by the key or keys stored
in the managed keys database.

The next time ``named`` runs after an ``initial-key`` or ``initial-ds`` has been *removed*
from the ``dnssec-keys`` statement (or changed to a ``static-key`` or ``static-ds``), the
corresponding zone will be removed from the managed keys database, and
:rfc:`5011` key maintenance will no longer be used for that domain.

In the current implementation, the managed keys database is stored as a
master-format zone file.

On servers which do not use views, this file is named
``managed-keys.bind``. When views are in use, there will be a separate
managed keys database for each view; the filename will be the view name
(or, if a view name contains characters which would make it illegal as a
filename, a hash of the view name), followed by the suffix ``.mkeys``.

When the key database is changed, the zone is updated. As with any other
dynamic zone, changes will be written into a journal file, e.g.,
``managed-keys.bind.jnl`` or ``internal.mkeys.jnl``. Changes are
committed to the master file as soon as possible afterward; this will
usually occur within 30 seconds. So, whenever ``named`` is using
automatic key maintenance, the zone file and journal file can be
expected to exist in the working directory. (For this reason among
others, the working directory should be always be writable by
``named``.)

If the ``dnssec-validation`` option is set to ``auto``, ``named`` will
automatically initialize an ``initial-key`` for the root zone. The key
that is used to initialize the key maintenance process is stored in
``bind.keys``; the location of this file can be overridden with the
``bindkeys-file`` option. As a fallback in the event no ``bind.keys``
can be found, the initializing key is also compiled directly into
``named``.

.. _dnssec_policy_grammar:

.. include:: ../misc/dnssec-policy.grammar.rst

.. _dnssec_policy:

The ``dnssec-policy`` statement defines a key and
signing policy (KASP) for zones.

A KASP determines how one or more zones will be signed
with DNSSEC. For example, it specifies how often keys should
roll, which cryptographic algorithms to use, and how often RRSIG
records need to be refreshed.

Keys are not shared among zones, which means that one set of keys
per zone will be generated even if they have the same policy.
If multiple views are configured with different versions of the
same zone, each separate version will use the same set of signing
keys.

Multiple key and signing policies can be configured.  To
attach a policy to a zone, add a ``dnssec-policy``
option to the ``zone`` statement, specifying he
name of the policy that should be used.

Key rollover timing is computed for each key according to
the key lifetime defined in the KASP.  The lifetime may be
modified by zone TTLs and propagation delays, in order to
prevent validation failures.  When a key reaches the end of its
lifetime,
``named`` will generate and publish a new key
automatically, then deactivate the old key and activate the
new one, and finally retire the old key according to a computed
schedule.

Zone-signing key (ZSK) rollovers require no operator input.
Key-signing key (KSK) and combined signing key (CSK) rollovers
require action to be taken to submit a DS record to the parent.
Rollover timing for KSKs and CSKs is adjusted to take into account
delays in processing and propagating DS updates.

There are two predefined ``dnssec-policy`` names:
``none`` and ``default``.
Setting a zone's policy to
``none`` is the same as not setting
``dnssec-policy`` at all; the zone will not
be signed.  Policy ``default`` causes the
zone to be signed with a single combined signing key (CSK)
using algorithm ECDSAP256SHA256; this key will have an
unlimited lifetime. (A verbose copy of this policy
may be found in the source tree, in the file
``doc/misc/dnssec-policy.default.conf``.)

.. note::

   The default signing policy may change in future releases.
   This could result in changes to your signing policy
   occurring when you upgrade to a new version of BIND. Check
   the release notes carefully when upgrading to be informed
   of such changes. To prevent policy changes on upgrade,
   use an explicitly defined ``dnssec-policy``
   rather than ``default``.

If a ``dnssec-policy`` statement is modified
and the server restarted or reconfigured, ``named``
will attempt to change the policy smoothly from the old one to
the new. For example, if the key algorithm is changed, then
a new key will be generated with the new algorithm, and the old
algorithm will be retired when the existing key's lifetime ends.

.. note::

  Rolling to a new policy while another key rollover is
  already in progress is not yet supported, and may result in
  unexpected behavior.

The following options can be specified in a ``dnssec-policy`` statement:

  ``dnskey-ttl``
    The TTL to use when generating DNSKEY resource records. The default is 1
    hour (3600 seconds).

  ``keys``
    A list specifying the algorithms and roles to use when
    generating keys and signing the zone.
    Entries in this list do not represent specific
    DNSSEC keys, which may be changed on a regular basis,
    but the roles that keys will play in the signing policy.
    For example, configuring a KSK of algorithm RSASHA256 ensures
    that the DNSKEY RRset will always include a key-signing key
    for that algorithm.

    Here is an example (for illustration purposes only) of
    some possible entries in a ``keys``
    list:

    ::

        keys {
               ksk key-directory lifetime unlimited algorithm rsasha1 2048;
               zsk lifetime P30D algorithm 8;
               csk lifetime P6MT12H3M15S algorithm ecdsa256;
	};

       This example specifies that three keys should be used
       in the zone. The first token determines which role the
       key will play in signing RRsets.  If set to
       ``ksk``, then this will be
       a key-signing key; it will have the KSK flag set and
       will only be used to sign DNSKEY, CDS, and CDNSKEY RRsets.
       If set to ``zsk``, this will be
       a zone-signing key; the KSK flag will be unset, and
       the key will sign all RRsets <emphasis>except</emphasis>
       DNSKEY, CDS, and CDNSKEY. If set to
       ``csk`` the key will have the KSK
       flag set and will be used to sign all RRsets.

       An optional second token determines where the key will
       be stored.  Currently, keys can only be stored in the
       configured ``key-directory``. This token
       may be used in the future to store keys in hardware
       service modules or separate directories.

       The ``lifetime`` parameter specifies how
       long a key may be used before rolling over.  In the
       example above, the first key will have an unlimited
       lifetime, the second key may be used for 30 days, and the
       third key has a rather peculiar lifetime of 6 months,
       12 hours, 3 minutes and 15 seconds.  A lifetime of 0
       seconds is the same as ``unlimited``.

       Note that the lifetime of a key may be extended if
       retiring it too soon would cause validation failures.
       For example, if the key were configured to roll more
       frequently than its own TTL, its lifetime would
       automatically be extended to account for this.

       The ``algorithm`` parameter specifies
       the key's algorithm, expressed either as a string
       ("rsasha256", "ecdsa384", etc) or as a decimal number.
       An optional second parameter specifies the key's size
       in size in bits. If it is omitted, as shown in the
       example for the second and third keys, an appropriate
       default size for the algorithm will be used.

    ``publish-safety``
       A margin that is added to the pre-publication
       interval in rollover timing calculations to give some
       extra time to cover unforeseen events. This increases
       the time that keys are published before becoming active.
       The default is ``PT1H`` (1 hour).

     ``retire-safety``
       A margin that is added to the post-publication interval
       in rollover timing calculations to give some extra time
       to cover unforeseen events. This increases the time a key
       remains published after it is no longer active.  The
       default is ``PT1H`` (1 hour).

     ``signatures-refresh``
       This determines how frequently an RRSIG record needs to be
       refreshed.  The signature is renewed when the time until
       the expiration time is closer than the specified interval.
       The default is ``P5D`` (5 days), meaning
       signatures that will expire in 5 days or sooner will be
       refreshed.

     ``signatures-validity``
       The validity period of an RRSIG record (subject to
       inception offset and jitter). The default is
       ``P2W`` (2 weeks).

     ``signatures-validity-dnskey``
       Similar to ``signatures-validity`` but for
       DNSKEY records. The default is ``P2W``
       (2 weeks).

     ``max-zone-ttl``
       Like the ``max-zone-ttl`` zone option,
       this specifies the maximum permissible TTL value in
       seconds for the zone. When loading a zone file using
       a `masterfile-format` of
       ``text`` or ``raw``,
       any record encountered with a TTL higher than
       `max-zone-ttl` will be capped at the
       maximum permissible TTL value.

       This is needed in DNSSEC-maintained zones because when
       rolling to a new DNSKEY, the old key needs to remain
       available until RRSIG records have expired from caches.
       The `max-zone-ttl` option guarantees that
       the largest TTL in the zone will be no higher than the
       set value.

       .. note::
	  Because ``map``-format files
	  load directly into memory, this option cannot be
	  used with them.)

       The default value is ``PT24H`` (24 hours).
       A `max-zone-ttl` of zero is treated as if
       the default value were in use.

     ``zone-propagation-delay``
       The expected propagation delay from the time when a zone
       is first updated to the time when the new version of the
       zone will be served by all secondary servers.  The default
       is ``PT5M`` (5 minutes).

     ``parent-ds-ttl``
       The TTL of the DS RRset that the parent zone uses.  The
       default is ``P1D`` (1 day).

     ``parent-propagation-delay``
       The expected propagation delay from the time when the
       parent zone is updated to the time when the new version
       is served by all of the parent zone's name servers.
       The default is ``PT1H`` (1 hour).

     ``parent-registration-delay``
       The expected registration delay from the time when a DS
       RRset change is requested to the time when the DS RRset
       will be updated in the parent zone.  The default is
       ``P1D`` (1 day).

.. _managed-keys:

``managed-keys`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/managed-keys.grammar.rst

.. _managed_keys:

``managed-keys`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``managed-keys`` statement has been
deprecated in favor of :ref:`trust_anchors`
with the ``initial-key`` keyword.

.. _trusted-keys:

``trusted-keys`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/trusted-keys.grammar.rst

.. _trusted_keys:

``trusted-keys`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``trusted-keys`` statement has been deprecated in favor of
:ref:`trust_anchors` with the ``static-key`` keyword.

.. _view_statement_grammar:

``view`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   view view_name [ class ] {
       match-clients { address_match_list } ;
       match-destinations { address_match_list } ;
       match-recursive-only yes_or_no ;
     [ view_option ; ... ]
     [ zone_statement ; ... ]
   } ;

.. _view_statement:

``view`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``view`` statement is a powerful feature of BIND 9 that lets a name
server answer a DNS query differently depending on who is asking. It is
particularly useful for implementing split DNS setups without having to
run multiple servers.

Each ``view`` statement defines a view of the DNS namespace that will be
seen by a subset of clients. A client matches a view if its source IP
address matches the ``address_match_list`` of the view's
``match-clients`` clause and its destination IP address matches the
``address_match_list`` of the view's ``match-destinations`` clause. If
not specified, both ``match-clients`` and ``match-destinations`` default
to matching all addresses. In addition to checking IP addresses
``match-clients`` and ``match-destinations`` can also take ``keys``
which provide an mechanism for the client to select the view. A view can
also be specified as ``match-recursive-only``, which means that only
recursive requests from matching clients will match that view. The order
of the ``view`` statements is significant — a client request will be
resolved in the context of the first ``view`` that it matches.

Zones defined within a ``view`` statement will only be accessible to
clients that match the ``view``. By defining a zone of the same name in
multiple views, different zone data can be given to different clients,
for example, "internal" and "external" clients in a split DNS setup.

Many of the options given in the ``options`` statement can also be used
within a ``view`` statement, and then apply only when resolving queries
with that view. When no view-specific value is given, the value in the
``options`` statement is used as a default. Also, zone options can have
default values specified in the ``view`` statement; these view-specific
defaults take precedence over those in the ``options`` statement.

Views are class specific. If no class is given, class IN is assumed.
Note that all non-IN views must contain a hint zone, since only the IN
class has compiled-in default hints.

If there are no ``view`` statements in the config file, a default view
that matches any client is automatically created in class IN. Any
``zone`` statements specified on the top level of the configuration file
are considered to be part of this default view, and the ``options``
statement will apply to the default view. If any explicit ``view``
statements are present, all ``zone`` statements must occur inside
``view`` statements.

Here is an example of a typical split DNS setup implemented using
``view`` statements:

::

   view "internal" {
         // This should match our internal networks.
         match-clients { 10.0.0.0/8; };

         // Provide recursive service to internal
         // clients only.
         recursion yes;

         // Provide a complete view of the example.com
         // zone including addresses of internal hosts.
         zone "example.com" {
           type master;
           file "example-internal.db";
         };
   };

   view "external" {
         // Match all clients not matched by the
         // previous view.
         match-clients { any; };

         // Refuse recursive service to external clients.
         recursion no;

         // Provide a restricted view of the example.com
         // zone containing only publicly accessible hosts.
         zone "example.com" {
          type master;
          file "example-external.db";
         };
   };

.. _zone_statement_grammar:

``zone`` Statement Grammar
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. include:: ../misc/master.zoneopt.rst
.. include:: ../misc/slave.zoneopt.rst
.. include:: ../misc/mirror.zoneopt.rst
.. include:: ../misc/hint.zoneopt.rst
.. include:: ../misc/stub.zoneopt.rst
.. include:: ../misc/static-stub.zoneopt.rst
.. include:: ../misc/forward.zoneopt.rst
.. include:: ../misc/redirect.zoneopt.rst
.. include:: ../misc/delegation-only.zoneopt.rst
.. include:: ../misc/in-view.zoneopt.rst

.. _zone_statement:

``zone`` Statement Definition and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _zone_types:

Zone Types
^^^^^^^^^^

The ``type`` keyword is required for the ``zone`` configuration unless
it is an ``in-view`` configuration. Its acceptable values include:
``primary`` (or ``master``), ``secondary`` (or ``slave``), ``mirror``,
``delegation-only``, ``forward``, ``hint``, ``redirect``,
``static-stub``, and ``stub``.

``primary``
   The server has a master copy of the data for the zone and will be able
   to provide authoritative answers for it. Type ``master`` is a synonym
   for ``primary``.

``secondary``
    A secondary zone is a replica of a primary zone. Type ``slave`` is a
    synonym for ``secondary``. The ``masters`` list specifies one or more IP
    addresses of master servers that the slave contacts to update
    its copy of the zone.  Masters list elements can
    also be names of other masters lists.  By default,
    transfers are made from port 53 on the servers;
    this can be changed for all servers by specifying
    a port number before the list of IP addresses,
    or on a per-server basis after the IP address.
    Authentication to the master can also be done with
    per-server TSIG keys.  If a file is specified, then the
    replica will be written to this file
    whenever the zone
    is changed, and reloaded from this file on a server
    restart. Use of a file is recommended, since it
    often speeds server startup and eliminates a
    needless waste of bandwidth. Note that for large
    numbers (in the tens or hundreds of thousands) of
    zones per server, it is best to use a two-level
    naming scheme for zone filenames. For example,
    a slave server for the zone
    ``example.com`` might place
    the zone contents into a file called
    ``ex/example.com`` where
    ``ex/`` is just the first two
    letters of the zone name. (Most operating systems
    behave very slowly if you put 100000 files into a single directory.)

``stub``
   A stub zone is similar to a slave zone, except that it replicates only
   the NS records of a master zone instead of the entire zone. Stub zones
   are not a standard part of the DNS; they are a feature specific to the
   BIND implementation.

   Stub zones can be used to eliminate the need for glue NS record in a parent
   zone at the expense of maintaining a stub zone entry and a set of name
   server addresses in ``named.conf``. This usage is not recommended for
   new configurations, and BIND 9 supports it only in a limited way. In BIND
   4/8, zone transfers of a parent zone included the NS records from stub
   children of that zone. This meant that, in some cases, users could get
   away with configuring child stubs only in the master server for the parent
   zone. BIND 9 never mixes together zone data from different zones in this
   way. Therefore, if a BIND 9 master serving a parent zone has child stub
   zones configured, all the slave servers for the parent zone also need to
   have the same child stub zones configured.

   Stub zones can also be used as a way of forcing the resolution of a given
   domain to use a particular set of authoritative servers. For example, the
   caching name servers on a private network using :rfc:`1918` addressing may be
   configured with stub zones for ``10.in-addr.arpa`` to use a set of
   internal name servers as the authoritative servers for that domain.

``mirror``

   A mirror zone is similar to a zone of type ``secondary``, except its data is
   subject to DNSSEC validation before being used in answers.  Validation is
   applied to the entire zone during the zone transfer process, and again when
   the zone file is loaded from disk when ``named`` is restarted.  If validation
   of a new version of a mirror zone fails, a retransfer is scheduled and the
   most recent correctly validated version of that zone is used until it either
   expires or a newer version validates correctly. If no usable zone data is
   available for a mirror zone at all, either due to transfer failure or
   expiration, traditional DNS recursion is used to look up the answers instead.
   Mirror zones cannot be used in a view that does not have recursion enabled.

   Answers coming from a mirror zone look almost exactly like answers from a
   zone of type ``secondary``, with the notable exceptions that the AA bit
   ("authoritative answer") is not set, and the AD bit ("authenticated data")
   is.

   Mirror zones are intended to be used to set up a fast local copy of the root
   zone, similar to the one described in RFC 7706.  A default list of primary
   servers for the IANA root zone is built into ``named`` and thus its mirroring
   can be enabled using the following configuration:


      ::

         zone "." {
              type mirror;
         };

   Other zones can be configured as mirror zones, but this should be considered
   *experimental* and may cause performance issues, especially with zones that
   are large and/or frequently updated.  Mirroring a zone other than root
   requires an explicit list of primary servers to be provided using the
   ``masters`` option (see :ref:`masters_grammar` for details), and a
   key-signing key (KSK) for the specified zone to be explicitly configured as a
   trust anchor.

   To make mirror zone contents persist between ``named`` restarts, use the
   :ref:`file <file-option>` option.


   When configuring NOTIFY for a mirror zone, only ``notify no;`` and ``notify
   explicit;`` can be used at the zone level.  Using any other ``notify``
   setting at the zone level is a configuration error. Using any other
   ``notify`` setting at the ``options`` or ``view`` level will cause that
   setting to be overridden with ``notify explicit;`` for the mirror zone.  The
   global default for the ``notify`` option is ``yes``, so mirror zones are by
   default configured with ``notify explicit;``.

   Outgoing transfers of mirror zones are disabled by default but may be
   enabled using :ref:`allow-transfer <allow-transfer-access>`.

   .. note::
      Using this zone type with any zone other than the root zone should
      be considered *experimental* and may cause performance issues, especially
      for zones which are large and/or frequently updated.

``static-stub``
   A static-stub zone is similar to a stub zone with the following
   exceptions: the zone data is statically configured, rather than
   transferred from a master server; when recursion is necessary for a query
   that matches a static-stub zone, the locally configured data (nameserver
   names and glue addresses) is always used even if different authoritative
   information is cached.

   Zone data is configured via the ``server-addresses`` and ``server-names``
   zone options.

   The zone data is maintained in the form of NS and (if necessary) glue A or
   AAAA RRs internally, which can be seen by dumping zone databases by
   ``rndc dumpdb -all``. The configured RRs are considered local configuration
   parameters rather than public data. Non recursive queries (i.e., those
   with the RD bit off) to a static-stub zone are therefore prohibited and
   will be responded with REFUSED.

   Since the data is statically configured, no zone maintenance action takes
   place for a static-stub zone. For example, there is no periodic refresh
   attempt, and an incoming notify message will be rejected with an rcode
   of NOTAUTH.

   Each static-stub zone is configured with internally generated NS and (if
   necessary) glue A or AAAA RRs

``forward``
   A "forward zone" is a way to configure forwarding on a per-domain basis.
   A ``zone`` statement of type ``forward`` can contain a ``forward`` and/or
   ``forwarders`` statement, which will apply to queries within the domain
   given by the zone name. If no ``forwarders`` statement is present or an
   empty list for ``forwarders`` is given, then no forwarding will be done
   for the domain, canceling the effects of any forwarders in the ``options``
   statement. Thus if you want to use this type of zone to change the
   behavior of the global ``forward`` option (that is, "forward first" to,
   then "forward only", or vice versa, but want to use the same servers as set
   globally) you need to re-specify the global forwarders.

``hint``
   The initial set of root name servers is specified using a "hint zone".
   When the server starts up, it uses the root hints to find a root name
   server and get the most recent list of root name servers. If no hint zone
   is specified for class IN, the server uses a compiled-in default set of
   root servers hints. Classes other than IN have no built-in defaults hints.

``redirect``
   Redirect zones are used to provide answers to queries when normal
   resolution would result in NXDOMAIN being returned. Only one redirect zone
   is supported per view. ``allow-query`` can be used to restrict which
   clients see these answers.

   If the client has requested DNSSEC records (DO=1) and the NXDOMAIN response
   is signed then no substitution will occur.

   To redirect all NXDOMAIN responses to 100.100.100.2 and
   2001:ffff:ffff::100.100.100.2, one would configure a type redirect zone
   named ".", with the zone file containing wildcard records that point to
   the desired addresses: ``"*. IN A 100.100.100.2"`` and
   ``"*. IN AAAA 2001:ffff:ffff::100.100.100.2"``.

   To redirect all Spanish names (under .ES) one would use similar entries
   but with the names ``*.ES.`` instead of ``*.``. To redirect all commercial
   Spanish names (under COM.ES) one would use wildcard entries
   called ``*.COM.ES.``.

   Note that the redirect zone supports all possible types; it is not
   limited to A and AAAA records.

   If a redirect zone is configured with a ``masters`` option, then it is
   transferred in as if it were a slave zone. Otherwise, it is loaded from a
   file as if it were a master zone.

   Because redirect zones are not referenced directly by name, they are not
   kept in the zone lookup table with normal master and slave zones. To reload
   a redirect zone, use ``rndc reload -redirect``, and to retransfer a
   redirect zone configured as slave, use ``rndc retransfer -redirect``.
   When using ``rndc reload`` without specifying a zone name, redirect
   zones will be reloaded along with other zones.

``delegation-only``
   This is used to enforce the delegation-only status of infrastructure
   zones (e.g. COM, NET, ORG). Any answer that is received without an
   explicit or implicit delegation in the authority section will be treated
   as NXDOMAIN. This does not apply to the zone apex. This should not be
   applied to leaf zones.

   ``delegation-only`` has no effect on answers received from forwarders.

   See caveats in :ref:`root-delegation-only <root-delegation-only>`.

Class
^^^^^

The zone's name may optionally be followed by a class. If a class is not
specified, class ``IN`` (for ``Internet``), is assumed. This is correct
for the vast majority of cases.

The ``hesiod`` class is named for an information service from MIT's
Project Athena. It is used to share information about various systems
databases, such as users, groups, printers and so on. The keyword ``HS``
is a synonym for hesiod.

Another MIT development is Chaosnet, a LAN protocol created in the
mid-1970s. Zone data for it can be specified with the ``CHAOS`` class.

.. _zone_options:

Zone Options
^^^^^^^^^^^^

``allow-notify``
   See the description of ``allow-notify`` in :ref:`access_control`.

``allow-query``
   See the description of ``allow-query`` in :ref:`access_control`.

``allow-query-on``
   See the description of ``allow-query-on`` in :ref:`access_control`.

``allow-transfer``
   See the description of ``allow-transfer`` in :ref:`access_control`.

``allow-update``
   See the description of ``allow-update`` in :ref:`access_control`.

``update-policy``
   Specifies a "Simple Secure Update" policy. See :ref:`dynamic_update_policies`.

``allow-update-forwarding``
   See the description of ``allow-update-forwarding`` in :ref:`access_control`.

``also-notify``
   Only meaningful if ``notify`` is active for this zone. The set of
   machines that will receive a ``DNS NOTIFY`` message for this zone is
   made up of all the listed name servers (other than the primary
   master) for the zone plus any IP addresses specified with
   ``also-notify``. A port may be specified with each ``also-notify``
   address to send the notify messages to a port other than the default
   of 53. A TSIG key may also be specified to cause the ``NOTIFY`` to be
   signed by the given key. ``also-notify`` is not meaningful for stub
   zones. The default is the empty list.

``check-names``
   This option is used to restrict the character set and syntax of
   certain domain names in master files and/or DNS responses received
   from the network. The default varies according to zone type. For
   ``master`` zones the default is ``fail``. For ``slave`` zones the
   default is ``warn``. It is not implemented for ``hint`` zones.

``check-mx``
   See the description of ``check-mx`` in :ref:`boolean_options`.

``check-spf``
   See the description of ``check-spf`` in :ref:`boolean_options`.

``check-wildcard``
   See the description of ``check-wildcard`` in :ref:`boolean_options`.

``check-integrity``
   See the description of ``check-integrity`` in :ref:`boolean_options`.

``check-sibling``
   See the description of ``check-sibling`` in :ref:`boolean_options`.

``zero-no-soa-ttl``
   See the description of ``zero-no-soa-ttl`` in :ref:`boolean_options`.

``update-check-ksk``
   See the description of ``update-check-ksk`` in :ref:`boolean_options`.

``dnssec-loadkeys-interval``
   See the description of ``dnssec-loadkeys-interval`` in :ref:`options`.

``dnssec-update-mode``
   See the description of ``dnssec-update-mode`` in :ref:`options`.

``dnssec-dnskey-kskonly``
   See the description of ``dnssec-dnskey-kskonly`` in :ref:`boolean_options`.

``try-tcp-refresh``
   See the description of ``try-tcp-refresh`` in :ref:`boolean_options`.

``database``
   Specify the type of database to be used for storing the zone data.
   The string following the ``database`` keyword is interpreted as a
   list of whitespace-delimited words. The first word identifies the
   database type, and any subsequent words are passed as arguments to
   the database to be interpreted in a way specific to the database
   type.

   The default is ``"rbt"``, BIND 9's native in-memory red-black-tree
   database. This database does not take arguments.

   Other values are possible if additional database drivers have been
   linked into the server. Some sample drivers are included with the
   distribution but none are linked in by default.

``dialup``
   See the description of ``dialup`` in :ref:`boolean_options`.

``delegation-only``
   The flag only applies to forward, hint and stub zones. If set to
   ``yes``, then the zone will also be treated as if it is also a
   delegation-only type zone.

   See caveats in :ref:`root-delegation-only <root-delegation-only>`.

.. _file-option:

``file``
   Set the zone's filename. In ``master``, ``hint``, and ``redirect``
   zones which do not have ``masters`` defined, zone data is loaded from
   this file. In ``slave``, ``mirror``, ``stub``, and ``redirect`` zones
   which do have ``masters`` defined, zone data is retrieved from
   another server and saved in this file. This option is not applicable
   to other zone types.

``forward``
   Only meaningful if the zone has a forwarders list. The ``only`` value
   causes the lookup to fail after trying the forwarders and getting no
   answer, while ``first`` would allow a normal lookup to be tried.

``forwarders``
   Used to override the list of global forwarders. If it is not
   specified in a zone of type ``forward``, no forwarding is done for
   the zone and the global options are not used.

``journal``
   Allow the default journal's filename to be overridden. The default is
   the zone's filename with "``.jnl``" appended. This is applicable to
   ``master`` and ``slave`` zones.

``max-ixfr-ratio``
   See the description of ``max-ixfr-ratio`` in :ref:`options`.

``max-journal-size``
   See the description of ``max-journal-size`` in :ref:`server_resource_limits`.

``max-records``
   See the description of ``max-records`` in :ref:`server_resource_limits`.

``max-transfer-time-in``
   See the description of ``max-transfer-time-in`` in :ref:`zone_transfers`.

``max-transfer-idle-in``
   See the description of ``max-transfer-idle-in`` in :ref:`zone_transfers`.

``max-transfer-time-out``
   See the description of ``max-transfer-time-out`` in :ref:`zone_transfers`.

``max-transfer-idle-out``
   See the description of ``max-transfer-idle-out`` in :ref:`zone_transfers`.

``notify``
   See the description of ``notify`` in :ref:`boolean_options`.

``notify-delay``
   See the description of ``notify-delay`` in :ref:`tuning`.

``notify-to-soa``
   See the description of ``notify-to-soa`` in :ref:`boolean_options`.

``zone-statistics``
   See the description of ``zone-statistics`` in :ref:`options`.

``server-addresses``
   Only meaningful for static-stub zones. This is a list of IP addresses
   to which queries should be sent in recursive resolution for the zone.
   A non empty list for this option will internally configure the apex
   NS RR with associated glue A or AAAA RRs.

   For example, if "example.com" is configured as a static-stub zone
   with 192.0.2.1 and 2001:db8::1234 in a ``server-addresses`` option,
   the following RRs will be internally configured.

   ::

      example.com. NS example.com.
      example.com. A 192.0.2.1
      example.com. AAAA 2001:db8::1234

   These records are internally used to resolve names under the
   static-stub zone. For instance, if the server receives a query for
   "www.example.com" with the RD bit on, the server will initiate
   recursive resolution and send queries to 192.0.2.1 and/or
   2001:db8::1234.

``server-names``
   Only meaningful for static-stub zones. This is a list of domain names
   of nameservers that act as authoritative servers of the static-stub
   zone. These names will be resolved to IP addresses when ``named``
   needs to send queries to these servers. To make this supplemental
   resolution successful, these names must not be a subdomain of the
   origin name of static-stub zone. That is, when "example.net" is the
   origin of a static-stub zone, "ns.example" and "master.example.com"
   can be specified in the ``server-names`` option, but "ns.example.net"
   cannot, and will be rejected by the configuration parser.

   A non empty list for this option will internally configure the apex
   NS RR with the specified names. For example, if "example.com" is
   configured as a static-stub zone with "ns1.example.net" and
   "ns2.example.net" in a ``server-names`` option, the following RRs
   will be internally configured.

   ::

      example.com. NS ns1.example.net.
      example.com. NS ns2.example.net.

   These records are internally used to resolve names under the
   static-stub zone. For instance, if the server receives a query for
   "www.example.com" with the RD bit on, the server initiate recursive
   resolution, resolve "ns1.example.net" and/or "ns2.example.net" to IP
   addresses, and then send queries to (one or more of) these addresses.

``sig-validity-interval``
   See the description of ``sig-validity-interval`` in :ref:`tuning`.

``sig-signing-nodes``
   See the description of ``sig-signing-nodes`` in :ref:`tuning`.

``sig-signing-signatures``
   See the description of ``sig-signing-signatures`` in
   :ref:`tuning`.

``sig-signing-type``
   See the description of ``sig-signing-type`` in :ref:`tuning`.

``transfer-source``
   See the description of ``transfer-source`` in :ref:`zone_transfers`.

``transfer-source-v6``
   See the description of ``transfer-source-v6`` in :ref:`zone_transfers`.

``alt-transfer-source``
   See the description of ``alt-transfer-source`` in :ref:`zone_transfers`.

``alt-transfer-source-v6``
   See the description of ``alt-transfer-source-v6`` in :ref:`zone_transfers`.

``use-alt-transfer-source``
   See the description of ``use-alt-transfer-source`` in :ref:`zone_transfers`.

``notify-source``
   See the description of ``notify-source`` in :ref:`zone_transfers`.

``notify-source-v6``
   See the description of ``notify-source-v6`` in :ref:`zone_transfers`.

``min-refresh-time``; \ ``max-refresh-time``; \ ``min-retry-time``; \ ``max-retry-time``
   See the description in :ref:`tuning`.

``ixfr-from-differences``
   See the description of ``ixfr-from-differences`` in :ref:`boolean_options`.
   (Note that the ``ixfr-from-differences`` ``master`` and ``slave``
   choices are not available at the zone level.)

``key-directory``
   See the description of ``key-directory`` in :ref:`options`.

``auto-dnssec``
   See the description of ``auto-dnssec`` in :ref:`options`.

``serial-update-method``
   See the description of ``serial-update-method`` in :ref:`options`.

``inline-signing``
   If ``yes``, this enables "bump in the wire" signing of a zone, where
   a unsigned zone is transferred in or loaded from disk and a signed
   version of the zone is served, with possibly, a different serial
   number. This behavior is disabled by default.

``multi-master``
   See the description of ``multi-master`` in :ref:`boolean_options`.

``masterfile-format``
   See the description of ``masterfile-format`` in :ref:`tuning`.

``max-zone-ttl``
   See the description of ``max-zone-ttl`` in :ref:`options`.

``dnssec-secure-to-insecure``
   See the description of ``dnssec-secure-to-insecure`` in :ref:`boolean_options`.

.. _dynamic_update_policies:

Dynamic Update Policies
^^^^^^^^^^^^^^^^^^^^^^^

BIND 9 supports two alternative methods of granting clients the right to
perform dynamic updates to a zone, configured by the ``allow-update``
and ``update-policy`` option, respectively.

The ``allow-update`` clause is a simple access control list. Any client
that matches the ACL is granted permission to update any record in the
zone.

The ``update-policy`` clause allows more fine-grained control over what
updates are allowed. It specifies a set of rules, in which each rule
either grants or denies permission for one or more names in the zone to
be updated by one or more identities. Identity is determined by the key
that signed the update request using either TSIG or SIG(0). In most
cases, ``update-policy`` rules only apply to key-based identities. There
is no way to specify update permissions based on client source address.

``update-policy`` rules are only meaningful for zones of type
``master``, and are not allowed in any other zone type. It is a
configuration error to specify both ``allow-update`` and
``update-policy`` at the same time.

A pre-defined ``update-policy`` rule can be switched on with the command
``update-policy local;``. Using this in a zone causes ``named`` to
generate a TSIG session key when starting up and store it in a file;
this key can then be used by local clients to update the zone while
``named`` is running. By default, the session key is stored in the file
``/var/run/named/session.key``, the key name is "local-ddns", and the
key algorithm is HMAC-SHA256. These values are configurable with the
``session-keyfile``, ``session-keyname`` and ``session-keyalg`` options,
respectively. A client running on the local system, if run with
appropriate permissions, may read the session key from the key file and
use it to sign update requests. The zone's update policy will be set to
allow that key to change any record within the zone. Assuming the key
name is "local-ddns", this policy is equivalent to:

::

   update-policy { grant local-ddns zonesub any; };

...with the additional restriction that only clients connecting from the
local system will be permitted to send updates.

Note that only one session key is generated by ``named``; all zones
configured to use ``update-policy local`` will accept the same key.

The command ``nsupdate -l`` implements this feature, sending requests to
localhost and signing them using the key retrieved from the session key
file.

Other rule definitions look like this:

::

   ( grant | deny ) identity ruletype  name   types

Each rule grants or denies privileges. Rules are checked in the order in
which they are specified in the ``update-policy`` statement. Once a
message has successfully matched a rule, the operation is immediately
granted or denied, and no further rules are examined. There are 13 types
of rules; the rule type is specified by the ``ruletype`` field, and the
interpretation of other fields varies depending on the rule type.

In general, a rule is matched when the key that signed an update request
matches the ``identity`` field, the name of the record to be updated
matches the ``name`` field (in the manner specified by the ``ruletype``
field), and the type of the record to be updated matches the ``types``
field. Details for each rule type are described below.

The ``identity`` field must be set to a fully-qualified domain name. In
most cases, this represensts the name of the TSIG or SIG(0) key that
must be used to sign the update request. If the specified name is a
wildcard, it is subject to DNS wildcard expansion, and the rule may
apply to multiple identities. When a TKEY exchange has been used to
create a shared secret, the identity of the key used to authenticate the
TKEY exchange will be used as the identity of the shared secret. Some
rule types use identities matching the client's Kerberos principal (e.g,
``"host/machine@REALM"``) or Windows realm (``machine$@REALM``).

The name field also specifies a fully-qualified domain name. This often
represents the name of the record to be updated. Interpretation of this
field is dependent on rule type.

If no ``types`` are explicitly specified, then a rule matches all types
except RRSIG, NS, SOA, NSEC and NSEC3. Types may be specified by name,
including "ANY" (ANY matches all types except NSEC and NSEC3, which can
never be updated). Note that when an attempt is made to delete all
records associated with a name, the rules are checked for each existing
record type.

The ruletype field has 16 values: ``name``, ``subdomain``, ``wildcard``,
``self``, ``selfsub``, ``selfwild``, ``krb5-self``, ``ms-self``,
``krb5-selfsub``, ``ms-selfsub``, ``krb5-subdomain``, ``ms-subdomain``,
``tcp-self``, ``6to4-self``, ``zonesub``, and ``external``.

``name``
    Exact-match semantics. This rule matches when the name being updated is identical to the contents of the name field.

``subdomain``
    This rule matches when the name being updated is a subdomain of, or identical to, the contents of the name field.

``zonesub``
    This rule is similar to subdomain, except that it matches when the name being updated is a subdomain of the zone in which the ``update-policy`` statement appears. This obviates the need to type the zone name twice, and enables the use of a standard ``update-policy`` statement in multiple zones without modification.
    When this rule is used, the name field is omitted.

``wildcard``
    The name field is subject to DNS wildcard expansion, and this rule matches when the name being updated is a valid expansion of the wildcard.

  ``self``
    This rule matches when the name of the record being pdated matches the contents of the identity field. The name field is ignored. To avoid confusion, it is recommended that this field be set to the same value as the identity field or to "."
    The ``self`` rule type is most useful when allowing one key per name to update, where the key has the same name as the record to be updated. In this case, the identity field can be specified as ``*`` (an asterisk).

``selfsub``
    This rule is similar to ``self`` except that subdomains of ``self`` can also be updated.

``selfwild``
    This rule is similar to ``self`` except that only subdomains of ``self`` can be updated.

``ms-self``
    When a client sends an UPDATE using a Windows machine principal (for example, 'machine$@REALM'), this rule allows records with the absolute name of 'machine.REALM' to be updated.

    The realm to be matched is specified in the identity field.

    The name field has no effect on this rule; it should be set to "." as a placeholder.

    For example, ``grant EXAMPLE.COM ms-self . A AAAA`` allows any machine with a valid principal in the realm ``EXAMPLE.COM`` to update its own address records.

``ms-selfsub``
    This is similar to ``ms-self`` except it also allows updates to any subdomain of the name specified in the Windows machine principal, not just to the name itself.

``ms-subdomain``
    When a client sends an UPDATE using a Windows machine principal (for example, 'machine$@REALM'), this rule allows any machine in the specified realm to update any record in the zone or in a specified subdomain of the zone.

    The realm to be matched is specified in the identity field.

    The name field specifies the subdomain that may be updated. If set to "." (or any other name at or above the zone apex), any name in the zone can be updated.

    For example, if ``update-policy`` for the zone "example.com" includes ``grant EXAMPLE.COM ms-subdomain hosts.example.com. AA AAAA``, any machine with a valid principal in the realm ``EXAMPLE.COM`` will be able to update address records at or below "hosts.example.com".

``krb5-self``
    When a client sends an UPDATE using a Kerberos machine principal (for example, 'host/machine@REALM'), this rule allows records with the absolute name of 'machine' to be updated provided it has been authenticated by REALM. This is similar but not identical to ``ms-self`` due to the 'machine' part of the Kerberos principal being an absolute name instead of a unqualified name.

    The realm to be matched is specified in the identity field.

    The name field has no effect on this rule; it should be set to "." as a placeholder.

    For example, ``grant EXAMPLE.COM krb5-self . A AAAA`` allows any machine with a valid principal in the realm ``EXAMPLE.COM`` to update its own address records.

``krb5-selfsub``
    This is similar to ``krb5-self`` except it also allows updates to any subdomain of the name specified in the 'machine' part of the Kerberos principal, not just to the name itself.

``krb5-subdomain``
    This rule is identical to ``ms-subdomain``, except that it works with Kerberos machine principals (i.e., 'host/machine@REALM') rather than Windows machine principals.

``tcp-self``
    This rule allows updates that have been sent via TCP and for which the standard mapping from the client's IP address into the ``in-addr.arpa`` and ``ip6.arpa`` namespaces match the name to be updated. The ``identity`` field must match that name. The ``name`` field should be set to ".". Note that, since identity is based on the client's IP address, it is not necessary for update request messages to be signed.

    .. note::
        It is theoretically possible to spoof these TCP sessions.

``6to4-self``
    This allows the name matching a 6to4 IPv6 prefix, as specified in :rfc:`3056`, to be updated by any TCP connection from either the 6to4 network or from the corresponding IPv4 address. This is intended to allow NS or DNAME RRsets to be added to the ``ip6.arpa`` reverse tree.

    The ``identity`` field must match the 6to4 prefix in ``ip6.arpa``. The ``name`` field should be set to ".". Note that, since identity is based on the client's IP address, it is not necessary for update request messages to be signed.

    In addition, if specified for an ``ip6.arpa`` name outside of the ``2.0.0.2.ip6.arpa`` namespace, the corresponding /48 reverse name can be updated. For example, TCP/IPv6 connections from 2001:DB8:ED0C::/48 can update records at ``C.0.D.E.8.B.D.0.1.0.0.2.ip6.arpa``.

    .. note::
        It is theoretically possible to spoof these TCP sessions.

``external``
    This rule allows ``named`` to defer the decision of whether to allow a given update to an external daemon.

    The method of communicating with the daemon is specified in the identity field, the format of which is "``local:``\ path", where path is the location of a UNIX-domain socket. (Currently, "local" is the only  supported mechanism.)

    Requests to the external daemon are sent over the UNIX-domain socket as datagrams with the following format:

    ::

        Protocol version number (4 bytes, network byte order, currently 1)
        Request length (4 bytes, network byte order)
        Signer (null-terminated string)
        Name (null-terminated string)
        TCP source address (null-terminated string)
        Rdata type (null-terminated string)
        Key (null-terminated string)
        TKEY token length (4 bytes, network byte order)
        TKEY token (remainder of packet)

    The daemon replies with a four-byte value in network byte order, containing either 0 or 1; 0 indicates that the specified update is not permitted, and 1 indicates that it is.

.. _multiple_views:

Multiple views
^^^^^^^^^^^^^^

When multiple views are in use, a zone may be referenced by more than
one of them. Often, the views will contain different zones with the same
name, allowing different clients to receive different answers for the
same queries. At times, however, it is desirable for multiple views to
contain identical zones. The ``in-view`` zone option provides an
efficient way to do this: it allows a view to reference a zone that was
defined in a previously configured view. Example:

::

   view internal {
       match-clients { 10/8; };

       zone example.com {
       type master;
       file "example-external.db";
       };
   };

   view external {
       match-clients { any; };

       zone example.com {
       in-view internal;
       };
   };

An ``in-view`` option cannot refer to a view that is configured later in
the configuration file.

A ``zone`` statement which uses the ``in-view`` option may not use any
other options with the exception of ``forward`` and ``forwarders``.
(These options control the behavior of the containing view, rather than
changing the zone object itself.)

Zone level acls (e.g. allow-query, allow-transfer) and other
configuration details of the zone are all set in the view the referenced
zone is defined in. Care need to be taken to ensure that acls are wide
enough for all views referencing the zone.

An ``in-view`` zone cannot be used as a response policy zone.

An ``in-view`` zone is not intended to reference a ``forward`` zone.

.. _zone_file:

Zone File
---------

.. _types_of_resource_records_and_when_to_use_them:

Types of Resource Records and When to Use Them
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section, largely borrowed from :rfc:`1034`, describes the concept of a
Resource Record (RR) and explains when each is used. Since the
publication of :rfc:`1034`, several new RRs have been identified and
implemented in the DNS. These are also included.

Resource Records
^^^^^^^^^^^^^^^^

A domain name identifies a node. Each node has a set of resource
information, which may be empty. The set of resource information
associated with a particular name is composed of separate RRs. The order
of RRs in a set is not significant and need not be preserved by name
servers, resolvers, or other parts of the DNS. However, sorting of
multiple RRs is permitted for optimization purposes, for example, to
specify that a particular nearby server be tried first. See
:ref:`the_sortlist_statement` and :ref:`rrset_ordering`.

The components of a Resource Record are:

owner name
    The domain name where the RR is found.

type
    An encoded 16-bit value that specifies the type of the resource record.

TTL
    The time-to-live of the RR. This field is a 32-bit integer in units of seconds, and is primarily used by resolvers when they cache RRs. The TTL describes how long a RR can be cached before it should be discarded.

class
    An encoded 16-bit value that identifies a protocol family or instance of a protocol.

RDATA
    The resource data. The format of the data is type (and sometimes class) specific.

The following are *types* of valid RRs:

A
    A host address. In the IN class, this is a 32-bit IP address. Described in :rfc:`1035`.

AAAA
    IPv6 address. Described in :rfc:`1886`.

A6
    IPv6 address. This can be a partial address (a suffix)  and an indirection to the name where the rest of the address (the prefix) can be found. Experimental. Described in :rfc:`2874`.

AFSDB
    Location of AFS database servers. Experimental. Described in :rfc:`1183`.

AMTRELAY
    Automatic Multicast Tunneling Relay discovery record. Work in progress draft-ietf-mboned-driad-amt-discovery.

APL
    Address prefix list. Experimental. Described in :rfc:`3123`.

ATMA
    ATM Address.

AVC
    Application Visibility and Control record.

CAA
    Identifies which Certificate Authorities can issue certificates for this domain and what rules they need to follow when doing so. Defined in :rfc:`6844`.

CDNSKEY
    Identifies which DNSKEY records should be published as DS records in the parent zone.

CDS
    Contains the set of DS records that should be published by the parent zone.

CERT
    Holds a digital certificate. Described in :rfc:`2538`.

CNAME
    Identifies the canonical name of an alias. Described in :rfc:`1035`.

CSYNC
    Child-to-Parent Synchronization in DNS as described in :rfc:`7477`.

DHCID
    Is used for identifying which DHCP client is associated with this name. Described in :rfc:`4701`.

DLV
    A DNS Lookaside Validation record which contains the records that are used as trust anchors for zones in a DLV namespace. Described in :rfc:`4431`. Historical.

DNAME
    Replaces the domain name specified with another name to be looked up, effectively aliasing an entire subtree of the domain name space rather than a single record as in the case of the CNAME RR. Described in :rfc:`2672`.

DNSKEY
    Stores a public key associated with a signed DNS zone. Described in :rfc:`4034`.

DOA
    Implements the Digital Object Architecture over DNS. Experimental.

DS
    Stores the hash of a public key associated with a signed DNS zone. Described in :rfc:`4034`.

EID
    End Point Identifier.

EUI48
    A 48-bit EUI address. Described in :rfc:`7043`.

EUI64
    A 64-bit EUI address. Described in :rfc:`7043`.

GID
    Reserved.

GPOS
    Specifies the global position. Superseded by LOC.

HINFO
    Identifies the CPU and OS used by a host. Described in :rfc:`1035`.

HIP
    Host Identity Protocol Address. Described in :rfc:`5205`.

IPSECKEY
    Provides a method for storing IPsec keying material in DNS. Described in :rfc:`4025`.

ISDN
    Representation of ISDN addresses. Experimental. Described in :rfc:`1183`.

 KEY
    Stores a public key associated with a DNS name. Used in original DNSSEC; replaced by DNSKEY in DNSSECbis, but still used with SIG(0). Described in :rfc:`2535` and :rfc:`2931`.

KX
    Identifies a key exchanger for this DNS name. Described in :rfc:`2230`.

L32
    Holds 32-bit Locator values for Identifier-Locator Network Protocol. Described in :rfc:`6742`.

L64
    Holds 64-bit Locator values for Identifier-Locator Network Protocol. Described in :rfc:`6742`.
LOC
    For storing GPS info. Described in :rfc:`1876`.  Experimental.

LP
    Identifier-Locator Network Protocol. Described in :rfc:`6742`.

MB
    Mail Box. Historical.

MD
    Mail Destination. Historical.

MF
    Mail Forwarder. Historical.

MG
    Mail Group. Historical.

MINFO
    Mail Information.

MR
    Mail Rename. Historical.

MX
    Identifies a mail exchange for the domain with a 16-bit preference value (lower is better) followed by the host name of the mail exchange. Described in :rfc:`974`,  :rfc:`1035`.

NAPTR
    Name authority pointer. Described in :rfc:`2915`.

NID
    Holds values for Node Identifiers in Identifier-Locator Network Protocol. Described in :rfc:`6742`.

NINFO
    Contains zone status information.

NIMLOC
    Nimrod Locator.

NSAP
    A network service access point. Described in :rfc:`1706`.

NSAP-PTR
    Historical.

NS
    The authoritative name server for the domain. Described in :rfc:`1035`.

NSEC
    Used in DNSSECbis to securely indicate that RRs with an owner name in a certain name interval do not exist in a zone and indicate what RR types are present for an existing name. Described in :rfc:`4034`.

NSEC3
    Used in DNSSECbis to securely indicate that RRs with an owner name in a certain name interval do not exist in a zone and indicate what RR types are present for an existing name. NSEC3 differs from NSEC in that it prevents zone enumeration but is more computationally expensive on both the server and the client than NSEC.  Described in :rfc:`5155`.

NSEC3PARAM
    Used in DNSSECbis to tell the authoritative server which NSEC3 chains are available to use. Described in :rfc:`5155`.

NULL
    This is an opaque container.

NXT
    Used in DNSSEC to securely indicate that RRs with anowner name in a certain name interval do not exist in a zone and indicate what RR types are present for an existing name. Used in original DNSSEC; replaced by NSEC in DNSSECbis. Described in :rfc:`2535`.

OPENPGPKEY
    Used to hold an OPENPGPKEY.

PTR
    A pointer to another part of the domain name space. Described in :rfc:`1035`.

PX
    Provides mappings between :rfc:`822` and X.400 addresses. Described in :rfc:`2163`. addresses. Described in :rfc:`2163`.

RKEY
    Resource key.

RP
    Information on persons responsible for the domain. Experimental. Described in :rfc:`1183`.

RRSIG
    Contains DNSSECbis signature data. Described in :rfc:`4034`.

RT
    Route-through binding for hosts that do not have their own direct wide area network addresses. Experimental. Described in :rfc:`1183`.

SIG
    Contains DNSSEC signature data. Used in original DNSSEC; replaced by RRSIG in DNSSECbis, but still used for SIG(0). Described in :rfc:`2535` and :rfc:`2931`.

SINK
    The kitchen sink record.

SMIMEA
    The S/MIME Security Certificate Association.

SOA
    Identifies the start of a zone of authority. Described in :rfc:`1035`.

SPF
    Contains the Sender Policy Framework information for a given email domain. Described in :rfc:`4408`.

SRV
    Information about well known network services (replaces WKS). Described in :rfc:`2782`.

SSHFP
    Provides a way to securely publish a secure shell key's fingerprint. Described in :rfc:`4255`.
TA
    Trust Anchor. Experimental.

TALINK
    Trust Anchor Link. Experimental.

TLSA
    Transport Layer Security Certificate Association.  Described in :rfc:`6698`.

TXT
    Text records. Described in :rfc:`1035`.

UID
    Reserved.

UINFO
    Reserved.

UNSPEC
    Reserved. Historical.

URI
    Holds a URI. Described in :rfc:`7553`.

WKS
    Information about which well known network services, such as SMTP, that a domain supports. Historical.

X25
    Representation of X.25 network addresses. Experimental. Described in :rfc:`1183`.

ZONEMD
    Zone Message Digest. Work in progress draft-wessels-dns-zone-digest.

The following *classes* of resource records are currently valid in the
DNS:

IN
    The Internet.

CH
    Chaosnet, a LAN protocol created at MIT in the mid-1970s. Rarely used for its historical purpose, but reused for BIND's built-in server information zones, e.g., ``version.bind``.

HS
    Hesiod, an information service developed by MIT's Project Athena. It is used to share information about various systems databases, such as users, groups, printers and so on.

The owner name is often implicit, rather than forming an integral part
of the RR. For example, many name servers internally form tree or hash
structures for the name space, and chain RRs off nodes. The remaining RR
parts are the fixed header (type, class, TTL) which is consistent for
all RRs, and a variable part (RDATA) that fits the needs of the resource
being described.

The meaning of the TTL field is a time limit on how long an RR can be
kept in a cache. This limit does not apply to authoritative data in
zones; it is also timed out, but by the refreshing policies for the
zone. The TTL is assigned by the administrator for the zone where the
data originates. While short TTLs can be used to minimize caching, and a
zero TTL prohibits caching, the realities of Internet performance
suggest that these times should be on the order of days for the typical
host. If a change can be anticipated, the TTL can be reduced prior to
the change to minimize inconsistency during the change, and then
increased back to its former value following the change.

The data in the RDATA section of RRs is carried as a combination of
binary strings and domain names. The domain names are frequently used as
"pointers" to other data in the DNS.

.. _rr_text:

Textual expression of RRs
^^^^^^^^^^^^^^^^^^^^^^^^^

RRs are represented in binary form in the packets of the DNS protocol,
and are usually represented in highly encoded form when stored in a name
server or resolver. In the examples provided in :rfc:`1034`, a style
similar to that used in master files was employed in order to show the
contents of RRs. In this format, most RRs are shown on a single line,
although continuation lines are possible using parentheses.

The start of the line gives the owner of the RR. If a line begins with a
blank, then the owner is assumed to be the same as that of the previous
RR. Blank lines are often included for readability.

Following the owner, we list the TTL, type, and class of the RR. Class
and type use the mnemonics defined above, and TTL is an integer before
the type field. In order to avoid ambiguity in parsing, type and class
mnemonics are disjoint, TTLs are integers, and the type mnemonic is
always last. The IN class and TTL values are often omitted from examples
in the interests of clarity.

The resource data or RDATA section of the RR are given using knowledge
of the typical representation for the data.

For example, we might show the RRs carried in a message as:

 +---------------------+---------------+--------------------------------+
 | ``ISI.EDU.``        | ``MX``        | ``10 VENERA.ISI.EDU.``         |
 +---------------------+---------------+--------------------------------+
 |                     | ``MX``        | ``10 VAXA.ISI.EDU``            |
 +---------------------+---------------+--------------------------------+
 | ``VENERA.ISI.EDU``  | ``A``         | ``128.9.0.32``                 |
 +---------------------+---------------+--------------------------------+
 |                     | ``A``         | ``10.1.0.52``                  |
 +---------------------+---------------+--------------------------------+
 | ``VAXA.ISI.EDU``    | ``A``         | ``10.2.0.27``                  |
 +---------------------+---------------+--------------------------------+
 |                     | ``A``         | ``128.9.0.33``                 |
 +---------------------+---------------+--------------------------------+

The MX RRs have an RDATA section which consists of a 16-bit number
followed by a domain name. The address RRs use a standard IP address
format to contain a 32-bit internet address.

The above example shows six RRs, with two RRs at each of three domain
names.

Similarly we might see:

 +----------------------+---------------+-------------------------------+
 | ``XX.LCS.MIT.EDU.``  | ``IN A``      | ``10.0.0.44``                 |
 +----------------------+---------------+-------------------------------+
 |                      | ``CH A``      | ``MIT.EDU. 2420``             |
 +----------------------+---------------+-------------------------------+

This example shows two addresses for ``XX.LCS.MIT.EDU``, each of a
different class.

.. _mx_records:

Discussion of MX Records
~~~~~~~~~~~~~~~~~~~~~~~~

As described above, domain servers store information as a series of
resource records, each of which contains a particular piece of
information about a given domain name (which is usually, but not always,
a host). The simplest way to think of a RR is as a typed pair of data, a
domain name matched with a relevant datum, and stored with some
additional type information to help systems determine when the RR is
relevant.

MX records are used to control delivery of email. The data specified in
the record is a priority and a domain name. The priority controls the
order in which email delivery is attempted, with the lowest number
first. If two priorities are the same, a server is chosen randomly. If
no servers at a given priority are responding, the mail transport agent
will fall back to the next largest priority. Priority numbers do not
have any absolute meaning — they are relevant only respective to other
MX records for that domain name. The domain name given is the machine to
which the mail will be delivered. It *must* have an associated address
record (A or AAAA) — CNAME is not sufficient.

For a given domain, if there is both a CNAME record and an MX record,
the MX record is in error, and will be ignored. Instead, the mail will
be delivered to the server specified in the MX record pointed to by the
CNAME. For example:

 +------------------------+--------+--------+--------------+------------------------+
 | ``example.com.``       | ``IN`` | ``MX`` | ``10``       | ``mail.example.com.``  |
 +------------------------+--------+--------+--------------+------------------------+
 |                        | ``IN`` | ``MX`` | ``10``       | ``mail2.example.com.`` |
 +------------------------+--------+--------+--------------+------------------------+
 |                        | ``IN`` | ``MX`` | ``20``       | ``mail.backup.org.``   |
 +------------------------+--------+--------+--------------+------------------------+
 | ``mail.example.com.``  | ``IN`` | ``A``  | ``10.0.0.1`` |                        |
 +------------------------+--------+--------+--------------+------------------------+
 | ``mail2.example.com.`` | ``IN`` | ``A``  | ``10.0.0.2`` |                        |
 +------------------------+--------+--------+--------------+------------------------+

Mail delivery will be attempted to ``mail.example.com`` and
``mail2.example.com`` (in any order), and if neither of those succeed,
delivery to ``mail.backup.org`` will be attempted.

.. _Setting_TTLs:

Setting TTLs
~~~~~~~~~~~~

The time-to-live of the RR field is a 32-bit integer represented in
units of seconds, and is primarily used by resolvers when they cache
RRs. The TTL describes how long a RR can be cached before it should be
discarded. The following three types of TTL are currently used in a zone
file.

SOA
    The last field in the SOA is the negative caching TTL. This controls how long other servers will cache no-such-domain (NXDOMAIN) responses from you.

    The maximum time for negative caching is 3 hours (3h).

$TTL
    The $TTL directive at the top of the zone file (before the SOA) gives a default TTL for every RR without a specific TTL set.

RR TTLs
    Each RR can have a TTL as the second field in the RR, which will control how long other servers can cache it.

All of these TTLs default to units of seconds, though units can be
explicitly specified, for example, ``1h30m``.

.. _ipv4_reverse:

Inverse Mapping in IPv4
~~~~~~~~~~~~~~~~~~~~~~~

Reverse name resolution (that is, translation from IP address to name)
is achieved by means of the *in-addr.arpa* domain and PTR records.
Entries in the in-addr.arpa domain are made in least-to-most significant
order, read left to right. This is the opposite order to the way IP
addresses are usually written. Thus, a machine with an IP address of
10.1.2.3 would have a corresponding in-addr.arpa name of
3.2.1.10.in-addr.arpa. This name should have a PTR resource record whose
data field is the name of the machine or, optionally, multiple PTR
records if the machine has more than one name. For example, in the
[example.com] domain:

 +--------------+-------------------------------------------------------+
 | ``$ORIGIN``  | ``2.1.10.in-addr.arpa``                               |
 +--------------+-------------------------------------------------------+
 | ``3``        | ``IN PTR foo.example.com.``                           |
 +--------------+-------------------------------------------------------+

.. note::

   The ``$ORIGIN`` lines in the examples are for providing context to
   the examples only — they do not necessarily appear in the actual
   usage. They are only used here to indicate that the example is
   relative to the listed origin.

.. _zone_directives:

Other Zone File Directives
~~~~~~~~~~~~~~~~~~~~~~~~~~

The Master File Format was initially defined in :rfc:`1035` and has
subsequently been extended. While the Master File Format itself is class
independent all records in a Master File must be of the same class.

Master File Directives include ``$ORIGIN``, ``$INCLUDE``, and ``$TTL.``

.. _atsign:

The ``@`` (at-sign)
^^^^^^^^^^^^^^^^^^^

When used in the label (or name) field, the asperand or at-sign (@)
symbol represents the current origin. At the start of the zone file, it
is the <``zone_name``> (followed by trailing dot).

.. _origin_directive:

The ``$ORIGIN`` Directive
^^^^^^^^^^^^^^^^^^^^^^^^^

Syntax: ``$ORIGIN`` domain-name [comment]

``$ORIGIN`` sets the domain name that will be appended to any
unqualified records. When a zone is first read in there is an implicit
``$ORIGIN`` <``zone_name``>\ ``.`` (followed by trailing dot). The
current ``$ORIGIN`` is appended to the domain specified in the
``$ORIGIN`` argument if it is not absolute.

::

   $ORIGIN example.com.
   WWW     CNAME   MAIN-SERVER

is equivalent to

::

   WWW.EXAMPLE.COM. CNAME MAIN-SERVER.EXAMPLE.COM.

.. _include_directive:

The ``$INCLUDE`` Directive
^^^^^^^^^^^^^^^^^^^^^^^^^^

Syntax: ``$INCLUDE`` filename [origin] [comment]

Read and process the file ``filename`` as if it were included into the
file at this point. If ``origin`` is specified the file is processed
with ``$ORIGIN`` set to that value, otherwise the current ``$ORIGIN`` is
used.

The origin and the current domain name revert to the values they had
prior to the ``$INCLUDE`` once the file has been read.

   **Note**

   :rfc:`1035` specifies that the current origin should be restored after
   an ``$INCLUDE``, but it is silent on whether the current domain name
   should also be restored. BIND 9 restores both of them. This could be
   construed as a deviation from :rfc:`1035`, a feature, or both.

.. _ttl_directive:

The ``$TTL`` Directive
^^^^^^^^^^^^^^^^^^^^^^

Syntax: ``$TTL`` default-ttl [comment]

Set the default Time To Live (TTL) for subsequent records with undefined
TTLs. Valid TTLs are of the range 0-2147483647 seconds.

``$TTL`` is defined in :rfc:`2308`.

.. _generate_directive:

BIND Master File Extension: the ``$GENERATE`` Directive
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Syntax: ``$GENERATE`` range lhs [ttl] [class] type rhs [comment]

``$GENERATE`` is used to create a series of resource records that only
differ from each other by an iterator. ``$GENERATE`` can be used to
easily generate the sets of records required to support sub /24 reverse
delegations described in :rfc:`2317`: Classless IN-ADDR.ARPA delegation.

::

   $ORIGIN 0.0.192.IN-ADDR.ARPA.
   $GENERATE 1-2 @ NS SERVER$.EXAMPLE.
   $GENERATE 1-127 $ CNAME $.0

is equivalent to

::

   0.0.0.192.IN-ADDR.ARPA. NS SERVER1.EXAMPLE.
   0.0.0.192.IN-ADDR.ARPA. NS SERVER2.EXAMPLE.
   1.0.0.192.IN-ADDR.ARPA. CNAME 1.0.0.0.192.IN-ADDR.ARPA.
   2.0.0.192.IN-ADDR.ARPA. CNAME 2.0.0.0.192.IN-ADDR.ARPA.
   ...
   127.0.0.192.IN-ADDR.ARPA. CNAME 127.0.0.0.192.IN-ADDR.ARPA.

Generate a set of A and MX records. Note the MX's right hand side is a
quoted string. The quotes will be stripped when the right hand side is
processed.

::

   $ORIGIN EXAMPLE.
   $GENERATE 1-127 HOST-$ A 1.2.3.$
   $GENERATE 1-127 HOST-$ MX "0 ."

is equivalent to

::

   HOST-1.EXAMPLE.   A  1.2.3.1
   HOST-1.EXAMPLE.   MX 0 .
   HOST-2.EXAMPLE.   A  1.2.3.2
   HOST-2.EXAMPLE.   MX 0 .
   HOST-3.EXAMPLE.   A  1.2.3.3
   HOST-3.EXAMPLE.   MX 0 .
   ...
   HOST-127.EXAMPLE. A  1.2.3.127
   HOST-127.EXAMPLE. MX 0 .

``range``
    This can be one of two forms: start-stop or start-stop/step. If the first form is used, then step is set to 1. start, stop and step must be positive integers between 0 and (2^31)-1. start must not be larger than stop.

``lhs``
    This describes the owner name of the resource records to be created. Any single ``$`` (dollar sign) symbols within the ``lhs`` string are replaced by the iterator value. To get a $ in the output, you need to escape the ``$`` using a backslash ``\``, e.g. ``\$``. The ``$`` may optionally be followed by modifiers which change the offset from the iterator, field width and base.

    Modifiers are introduced by a ``{`` (left brace) immediately following the ``$`` as   ``${offset[,width[,base]]}``. For example, ``${-20,3,d}`` subtracts 20 from the current value, prints the result as a decimal in a zero-padded field of width 3. Available output forms are decimal (``d``), octal (``o``), hexadecimal (``x`` or ``X`` for uppercase) and nibble (``n`` or ``N``\\ for uppercase).

    The default modifier is ``${0,0,d}``. If the ``lhs`` is not absolute, the current ``$ORIGIN`` is appended to the name.

    In nibble mode the value will be treated as if it was a reversed hexadecimal string with each hexadecimal digit as a separate label. The width field includes the label separator.

    For compatibility with earlier versions, ``$$`` is still recognized as indicating a literal $ in the output.

``ttl``
    Specifies the time-to-live of the generated records. If not specified this will be inherited using the normal TTL inheritance rules.

    ``class`` and ``ttl`` can be entered in either order.

``class``
    Specifies the class of the generated records. This must match the zone class if it is specified.

    ``class`` and ``ttl`` can be entered in either order.

``type``
    Any valid type.

``rhs``
    ``rhs``, optionally, quoted string.

The ``$GENERATE`` directive is a BIND extension and not part of the
standard zone file format.

.. _zonefile_format:

Additional File Formats
~~~~~~~~~~~~~~~~~~~~~~~

In addition to the standard textual format, BIND 9 supports the ability
to read or dump to zone files in other formats.

The ``raw`` format is a binary representation of zone data in a manner
similar to that used in zone transfers. Since it does not require
parsing text, load time is significantly reduced.

An even faster alternative is the ``map`` format, which is an image of a
BIND 9 in-memory zone database; it is capable of being loaded directly
into memory via the ``mmap()`` function; the zone can begin serving
queries almost immediately.

For a primary server, a zone file in ``raw`` or ``map`` format is
expected to be generated from a textual zone file by the
``named-compilezone`` command. For a secondary server or for a dynamic
zone, it is automatically generated (if this format is specified by the
``masterfile-format`` option) when ``named`` dumps the zone contents
after zone transfer or when applying prior updates.

If a zone file in a binary format needs manual modification, it first
must be converted to a textual form by the ``named-compilezone``
command. All necessary modification should go to the text file, which
should then be converted to the binary form by the ``named-compilezone``
command again.

Note that ``map`` format is extremely architecture-specific. A ``map``
file *cannot* be used on a system with different pointer size,
endianness or data alignment than the system on which it was generated,
and should in general be used only inside a single system. While ``raw``
format uses network byte order and avoids architecture-dependent data
alignment so that it is as portable as possible, it is also primarily
expected to be used inside the same single system. To export a zone file
in either ``raw`` or ``map`` format, or make a portable backup of such a
file, conversion to ``text`` format is recommended.

.. _statistics:

BIND9 Statistics
----------------

BIND 9 maintains lots of statistics information and provides several
interfaces for users to get access to the statistics. The available
statistics include all statistics counters that were available in BIND 8
and are meaningful in BIND 9, and other information that is considered
useful.

The statistics information is categorized into the following sections:

Incoming Requests
   The number of incoming DNS requests for each OPCODE.

Incoming Queries
   The number of incoming queries for each RR type.

Outgoing Queries
   The number of outgoing queries for each RR type sent from the internal
   resolver. Maintained per view.

Name Server Statistics
   Statistics counters about incoming request processing.

Zone Maintenance Statistics
   Statistics counters regarding zone maintenance operations such as zone
   transfers.

Resolver Statistics
   Statistics counters about name resolution performed in the internal resolver.
   Maintained per view.

Cache DB RRsets

   Statistics counters related to cache contents; maintained per view.

   The "NXDOMAIN" counter is the number of names that have been cached as
   nonexistent.  Counters named for RR types indicate the number of active
   RRsets for each type in the cache database.

   If an RR type name is preceded by an exclamation mark (!), it represents the
   number of records in the cache which indicate that the type does not exist
   for a particular name (this is also known as "NXRRSET").  If an RR type name
   is preceded by a hash mark (#), it represents the number of RRsets for this
   type that are present in the cache but whose TTLs have expired; these RRsets
   may only be used if stale answers are enabled.  If an RR type name is
   preceded by a tilde (~), it represents the number of RRsets for this type
   that are present in the cache database but are marked for garbage collection;
   these RRsets cannot be used.

Socket I/O Statistics
   Statistics counters about network related events.


A subset of Name Server Statistics is collected and shown per zone for
which the server has the authority when ``zone-statistics`` is set to
``full`` (or ``yes`` for backward compatibility. See the description of
``zone-statistics`` in :ref:`options` for further details.

These statistics counters are shown with their zone and view names. The
view name is omitted when the server is not configured with explicit
views.

There are currently two user interfaces to get access to the statistics.
One is in the plain text format dumped to the file specified by the
``statistics-file`` configuration option. The other is remotely
accessible via a statistics channel when the ``statistics-channels``
statement is specified in the configuration file (see :ref:`statschannels`.)

.. _statsfile:

The Statistics File
~~~~~~~~~~~~~~~~~~~

The text format statistics dump begins with a line, like:

``+++ Statistics Dump +++ (973798949)``

The number in parentheses is a standard Unix-style timestamp, measured
as seconds since January 1, 1970. Following that line is a set of
statistics information, which is categorized as described above. Each
section begins with a line, like:

``++ Name Server Statistics ++``

Each section consists of lines, each containing the statistics counter
value followed by its textual description. See below for available
counters. For brevity, counters that have a value of 0 are not shown in
the statistics file.

The statistics dump ends with the line where the number is identical to
the number in the beginning line; for example:

``--- Statistics Dump --- (973798949)``

.. _statistics_counters:

Statistics Counters
~~~~~~~~~~~~~~~~~~~

The following tables summarize statistics counters that BIND 9 provides.
For each row of the tables, the leftmost column is the abbreviated
symbol name of that counter. These symbols are shown in the statistics
information accessed via an HTTP statistics channel. The rightmost
column gives the description of the counter, which is also shown in the
statistics file (but, in this document, possibly with slight
modification for better readability). Additional notes may also be
provided in this column. When a middle column exists between these two
columns, it gives the corresponding counter name of the BIND 8
statistics, if applicable.

.. _stats_counters:

Name Server Statistics Counters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

+------------------------+-------------+------------------------------------------------+
| *Symbol*               | *BIND8*     | *Description*                                  |
|                        | *Symbol*    |                                                |
+------------------------+-------------+------------------------------------------------+
| ``Requestv4``          | ``RQ``      | IPv4 requests received. Note: this also        |
|                        |             | counts non query requests.                     |
+------------------------+-------------+------------------------------------------------+
| ``Requestv6``          | ``RQ``      | IPv6 requests received. Note: this also        |
|                        |             | counts non query requests.                     |
+------------------------+-------------+------------------------------------------------+
| ``ReqEdns0``           |             | Requests with EDNS(0) received.                |
+------------------------+-------------+------------------------------------------------+
| ``ReqBadEDN SVer``     |             | Requests with unsupported EDNS version         |
|                        |             | received.                                      |
+------------------------+-------------+------------------------------------------------+
| ``ReqTSIG``            |             | Requests with TSIG received.                   |
+------------------------+-------------+------------------------------------------------+
| ``ReqSIG0``            |             | Requests with SIG(0) received.                 |
+------------------------+-------------+------------------------------------------------+
| ``ReqBadSIG``          |             | Requests with invalid (TSIG or SIG(0))         |
|                        |             | signature.                                     |
+------------------------+-------------+------------------------------------------------+
| ``ReqTCP``             | ``RTCP``    | TCP requests received.                         |
+------------------------+-------------+------------------------------------------------+
| ``AuthQryRej``         | ``RUQ``     | Authoritative (non recursive) queries          |
|                        |             | rejected.                                      |
+------------------------+-------------+------------------------------------------------+
| ``RecQryRej``          | ``RURQ``    | Recursive queries rejected.                    |
+------------------------+-------------+------------------------------------------------+
| ``XfrRej``             | ``RUXFR``   | Zone transfer requests rejected.               |
+------------------------+-------------+------------------------------------------------+
| ``UpdateRej``          | ``RUUpd``   | Dynamic update requests rejected.              |
+------------------------+-------------+------------------------------------------------+
| ``Response``           | ``SAns``    | Responses sent.                                |
+------------------------+-------------+------------------------------------------------+
| ``RespTruncated``      |             | Truncated responses sent.                      |
+------------------------+-------------+------------------------------------------------+
| ``RespEDNS0``          |             | Responses with EDNS(0) sent.                   |
+------------------------+-------------+------------------------------------------------+
| ``RespTSIG``           |             | Responses with TSIG sent.                      |
+------------------------+-------------+------------------------------------------------+
| ``RespSIG0``           |             | Responses with SIG(0) sent.                    |
+------------------------+-------------+------------------------------------------------+
| ``QrySuccess``         |             | Queries resulted in a successful               |
|                        |             | answer. This means the query which             |
|                        |             | returns a NOERROR response with at             |
|                        |             | least one answer RR. This corresponds          |
|                        |             | to the ``success`` counter of previous         |
|                        |             | versions of BIND 9.                            |
+------------------------+-------------+------------------------------------------------+
| ``QryAuthAns``         |             | Queries resulted in authoritative              |
|                        |             | answer.                                        |
+------------------------+-------------+------------------------------------------------+
| ``QryNoauthAns``       | ``SNaAns``  | Queries resulted in non authoritative          |
|                        |             | answer.                                        |
+------------------------+-------------+------------------------------------------------+
| ``QryReferral``        |             | Queries resulted in referral answer.           |
|                        |             | This corresponds to the ``referral``           |
|                        |             | counter of previous versions of BIND 9.        |
+------------------------+-------------+------------------------------------------------+
| ``QryNxrrset``         |             | Queries resulted in NOERROR responses          |
|                        |             | with no data. This corresponds to the          |
|                        |             | ``nxrrset`` counter of previous                |
|                        |             | versions of BIND 9.                            |
+------------------------+-------------+------------------------------------------------+
| ``QrySERVFAIL``        | ``SFail``   | Queries resulted in SERVFAIL.                  |
+------------------------+-------------+------------------------------------------------+
| ``QryFORMERR``         | ``SFErr``   | Queries resulted in FORMERR.                   |
+------------------------+-------------+------------------------------------------------+
| ``QryNXDOMAIN``        | ``SNXD``    | Queries resulted in NXDOMAIN. This             |
|                        |             | corresponds to the ``nxdomain`` counter        |
|                        |             | of previous versions of BIND 9.                |
+------------------------+-------------+------------------------------------------------+
| ``QryRecursion``       | ``RFwdQ``   | Queries which caused the server to             |
|                        |             | perform recursion in order to find the         |
|                        |             | final answer. This corresponds to the          |
|                        |             | ``recursion`` counter of previous              |
|                        |             | versions of BIND 9.                            |
+------------------------+-------------+------------------------------------------------+
| ``QryDuplicate``       | ``RDupQ``   | Queries which the server attempted to          |
|                        |             | recurse but discovered an existing             |
|                        |             | query with the same IP address, port,          |
|                        |             | query ID, name, type and class already         |
|                        |             | being processed. This corresponds to           |
|                        |             | the ``duplicate`` counter of previous          |
|                        |             | versions of BIND 9.                            |
+------------------------+-------------+------------------------------------------------+
| ``QryDropped``         |             | Recursive queries for which the server         |
|                        |             | discovered an excessive number of              |
|                        |             | existing recursive queries for the same        |
|                        |             | name, type and class and were                  |
|                        |             | subsequently dropped. This is the              |
|                        |             | number of dropped queries due to the           |
|                        |             | reason explained with the                      |
|                        |             | ``clients-per-query`` and                      |
|                        |             | ``max-clients-per-query`` options (see         |
|                        |             | :ref:`clients-per-query <clients-per-query>`). |
|                        |             | This corresponds to the ``dropped``            |
|                        |             | counter of previous versions of BIND 9.        |
+------------------------+-------------+------------------------------------------------+
| ``QryFailure``         |             | Other query failures. This corresponds         |
|                        |             | to the ``failure`` counter of previous         |
|                        |             | versions of BIND 9. Note: this counter         |
|                        |             | is provided mainly for backward                |
|                        |             | compatibility with the previous                |
|                        |             | versions. Normally a more fine-grained         |
|                        |             | counters such as ``AuthQryRej`` and            |
|                        |             | ``RecQryRej`` that would also fall into        |
|                        |             | this counter are provided, and so this         |
|                        |             | counter would not be of much interest          |
|                        |             | in practice.                                   |
+------------------------+-------------+------------------------------------------------+
| ``QryNXRedir``         |             | Queries resulted in NXDOMAIN that were         |
|                        |             | redirected.                                    |
+------------------------+-------------+------------------------------------------------+
| ``QryNXRedirRLookup``  |             | Queries resulted in NXDOMAIN that were         |
|                        |             | redirected and resulted in a successful        |
|                        |             | remote lookup.                                 |
+------------------------+-------------+------------------------------------------------+
| ``XfrReqDone``         |             | Requested zone transfers completed.            |
+------------------------+-------------+------------------------------------------------+
| ``UpdateReqFwd``       |             | Update requests forwarded.                     |
+------------------------+-------------+------------------------------------------------+
| ``UpdateRespFwd``      |             | Update responses forwarded.                    |
+------------------------+-------------+------------------------------------------------+
| ``UpdateFwdFail``      |             | Dynamic update forward failed.                 |
+------------------------+-------------+------------------------------------------------+
| ``UpdateDone``         |             | Dynamic updates completed.                     |
+------------------------+-------------+------------------------------------------------+
| ``UpdateFail``         |             | Dynamic updates failed.                        |
+------------------------+-------------+------------------------------------------------+
| ``UpdateBadPrereq``    |             | Dynamic updates rejected due to                |
|                        |             | prerequisite failure.                          |
+------------------------+-------------+------------------------------------------------+
| ``RateDropped``        |             | Responses dropped by rate limits.              |
+------------------------+-------------+------------------------------------------------+
| ``RateSlipped``        |             | Responses truncated by rate limits.            |
+------------------------+-------------+------------------------------------------------+
| ``RPZRewrites``        |             | Response policy zone rewrites.                 |
+------------------------+-------------+------------------------------------------------+

.. _zone_stats:

Zone Maintenance Statistics Counters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 +-----------------+----------------------------------------------------+
 | *Symbol*        | *Description*                                      |
 +-----------------+----------------------------------------------------+
 | ``NotifyOutv4`` | IPv4 notifies sent.                                |
 +-----------------+----------------------------------------------------+
 | ``NotifyOutv6`` | IPv6 notifies sent.                                |
 +-----------------+----------------------------------------------------+
 | ``NotifyInv4``  | IPv4 notifies received.                            |
 +-----------------+----------------------------------------------------+
 | ``NotifyInv6``  | IPv6 notifies received.                            |
 +-----------------+----------------------------------------------------+
 | ``NotifyRej``   | Incoming notifies rejected.                        |
 +-----------------+----------------------------------------------------+
 | ``SOAOutv4``    | IPv4 SOA queries sent.                             |
 +-----------------+----------------------------------------------------+
 | ``SOAOutv6``    | IPv6 SOA queries sent.                             |
 +-----------------+----------------------------------------------------+
 | ``AXFRReqv4``   | IPv4 AXFR requested.                               |
 +-----------------+----------------------------------------------------+
 | ``AXFRReqv6``   | IPv6 AXFR requested.                               |
 +-----------------+----------------------------------------------------+
 | ``IXFRReqv4``   | IPv4 IXFR requested.                               |
 +-----------------+----------------------------------------------------+
 | ``IXFRReqv6``   | IPv6 IXFR requested.                               |
 +-----------------+----------------------------------------------------+
 | ``XfrSuccess``  | Zone transfer requests succeeded.                  |
 +-----------------+----------------------------------------------------+
 | ``XfrFail``     | Zone transfer requests failed.                     |
 +-----------------+----------------------------------------------------+

.. _resolver_stats:

Resolver Statistics Counters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 +---------------------+-------------+-----------------------------------------+
 | *Symbol*            | *BIND8      | *Description*                           |
 |                     | Symbol*     |                                         |
 +---------------------+-------------+-----------------------------------------+
 | ``Queryv4``         | ``SFwdQ``   | IPv4 queries sent.                      |
 +---------------------+-------------+-----------------------------------------+
 | ``Queryv6``         | ``SFwdQ``   | IPv6 queries sent.                      |
 +---------------------+-------------+-----------------------------------------+
 | ``Responsev4``      | ``RR``      | IPv4 responses received.                |
 +---------------------+-------------+-----------------------------------------+
 | ``Responsev6``      | ``RR``      | IPv6 responses received.                |
 +---------------------+-------------+-----------------------------------------+
 | ``NXDOMAIN``        | ``RNXD``    | NXDOMAIN received.                      |
 +---------------------+-------------+-----------------------------------------+
 | ``SERVFAIL``        | ``RFail``   | SERVFAIL received.                      |
 +---------------------+-------------+-----------------------------------------+
 | ``FORMERR``         | ``RFErr``   | FORMERR received.                       |
 +---------------------+-------------+-----------------------------------------+
 | ``OtherError``      | ``RErr``    | Other errors received.                  |
 +---------------------+-------------+-----------------------------------------+
 | ``EDNS0Fail``       |             | EDNS(0) query failures.                 |
 +---------------------+-------------+-----------------------------------------+
 | ``Mismatch``        | ``RDupR``   | Mismatch responses received. The DNS    |
 |                     |             | ID, response's source address, and/or   |
 |                     |             | the response's source port does not     |
 |                     |             | match what was expected. (The port must |
 |                     |             | be 53 or as defined by the ``port``     |
 |                     |             | option.) This may be an indication of a |
 |                     |             | cache poisoning attempt.                |
 +---------------------+-------------+-----------------------------------------+
 | ``Truncated``       |             | Truncated responses received.           |
 +---------------------+-------------+-----------------------------------------+
 | ``Lame``            | ``RLame``   | Lame delegations received.              |
 +---------------------+-------------+-----------------------------------------+
 | ``Retry``           | ``SDupQ``   | Query retries performed.                |
 +---------------------+-------------+-----------------------------------------+
 | ``QueryAbort``      |             | Queries aborted due to quota control.   |
 +---------------------+-------------+-----------------------------------------+
 | ``QuerySockFail``   |             | Failures in opening query sockets. One  |
 |                     |             | common reason for such failures is a    |
 |                     |             | failure of opening a new socket due to  |
 |                     |             | a limitation on file descriptors.       |
 +---------------------+-------------+-----------------------------------------+
 | ``QueryTimeout``    |             | Query timeouts.                         |
 +---------------------+-------------+-----------------------------------------+
 | ``GlueFetchv4``     | ``SSysQ``   | IPv4 NS address fetches invoked.        |
 +---------------------+-------------+-----------------------------------------+
 | ``GlueFetchv6``     | ``SSysQ``   | IPv6 NS address fetches invoked.        |
 +---------------------+-------------+-----------------------------------------+
 | ``GlueFetchv4Fail`` |             | IPv4 NS address fetch failed.           |
 +---------------------+-------------+-----------------------------------------+
 | ``GlueFetchv6Fail`` |             | IPv6 NS address fetch failed.           |
 +---------------------+-------------+-----------------------------------------+
 | ``ValAttempt``      |             | DNSSEC validation attempted.            |
 +---------------------+-------------+-----------------------------------------+
 | ``ValOk``           |             | DNSSEC validation succeeded.            |
 +---------------------+-------------+-----------------------------------------+
 | ``ValNegOk``        |             | DNSSEC validation on negative           |
 |                     |             | information succeeded.                  |
 +---------------------+-------------+-----------------------------------------+
 | ``ValFail``         |             | DNSSEC validation failed.               |
 +---------------------+-------------+-----------------------------------------+
 | ``QryRTTnn``        |             | Frequency table on round trip times     |
 |                     |             | (RTTs) of queries. Each ``nn``          |
 |                     |             | specifies the corresponding frequency.  |
 |                     |             | In the sequence of ``nn_1``, ``nn_2``,  |
 |                     |             | ..., ``nn_m``, the value of ``nn_i`` is |
 |                     |             | the number of queries whose RTTs are    |
 |                     |             | between ``nn_(i-1)`` (inclusive) and    |
 |                     |             | ``nn_i`` (exclusive) milliseconds. For  |
 |                     |             | the sake of convenience we define       |
 |                     |             | ``nn_0`` to be 0. The last entry should |
 |                     |             | be represented as ``nn_m+``, which      |
 |                     |             | means the number of queries whose RTTs  |
 |                     |             | are equal to or over ``nn_m``           |
 |                     |             | milliseconds.                           |
 +---------------------+-------------+-----------------------------------------+

.. _socket_stats:

Socket I/O Statistics Counters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Socket I/O statistics counters are defined per socket types, which are
``UDP4`` (UDP/IPv4), ``UDP6`` (UDP/IPv6), ``TCP4`` (TCP/IPv4), ``TCP6``
(TCP/IPv6), ``Unix`` (Unix Domain), and ``FDwatch`` (sockets opened
outside the socket module). In the following table ``<TYPE>`` represents
a socket type. Not all counters are available for all socket types;
exceptions are noted in the description field.

 +----------------------+----------------------------------------------------+
 | *Symbol*             | *Description*                                      |
 +----------------------+----------------------------------------------------+
 | ``<TYPE>Open``       | Sockets opened successfully. This counter is not   |
 |                      | applicable to the ``FDwatch`` type.                |
 +----------------------+----------------------------------------------------+
 | ``<TYPE>OpenFail``   | Failures of opening sockets. This counter is not   |
 |                      | applicable to the ``FDwatch`` type.                |
 +----------------------+----------------------------------------------------+
 | ``<TYPE>Close``      | Sockets closed.                                    |
 +----------------------+----------------------------------------------------+
 | ``<TYPE>BindFail``   | Failures of binding sockets.                       |
 +----------------------+----------------------------------------------------+
 | ``<TYPE>ConnFail``   | Failures of connecting sockets.                    |
 +----------------------+----------------------------------------------------+
 | ``<TYPE>Conn``       | Connections established successfully.              |
 +----------------------+----------------------------------------------------+
 | ``<TYPE>AcceptFail`` | Failures of accepting incoming connection          |
 |                      | requests. This counter is not applicable to the    |
 |                      | ``UDP`` and ``FDwatch`` types.                     |
 +----------------------+----------------------------------------------------+
 | ``<TYPE>Accept``     | Incoming connections successfully accepted. This   |
 |                      | counter is not applicable to the ``UDP`` and       |
 |                      | ``FDwatch`` types.                                 |
 +----------------------+----------------------------------------------------+
 | ``<TYPE>SendErr``    | Errors in socket send operations. This counter     |
 |                      | corresponds to ``SErr`` counter of ``BIND`` 8.     |
 +----------------------+----------------------------------------------------+
 | ``<TYPE>RecvErr``    | Errors in socket receive operations. This includes |
 |                      | errors of send operations on a connected UDP       |
 |                      | socket notified by an ICMP error message.          |
 +----------------------+----------------------------------------------------+

.. _bind8_compatibility:

Compatibility with *BIND* 8 Counters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Most statistics counters that were available in ``BIND`` 8 are also
supported in ``BIND`` 9 as shown in the above tables. Here are notes
about other counters that do not appear in these tables.

``RFwdR,SFwdR``
   These counters are not supported because ``BIND`` 9 does not adopt
   the notion of *forwarding* as ``BIND`` 8 did.

``RAXFR``
   This counter is accessible in the Incoming Queries section.

``RIQ``
   This counter is accessible in the Incoming Requests section.

``ROpts``
   This counter is not supported because ``BIND`` 9 does not care about
   IP options in the first place.
