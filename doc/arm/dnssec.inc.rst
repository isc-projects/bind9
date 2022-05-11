.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

.. _dnssec:

DNSSEC
------

Cryptographic authentication of DNS information is possible through the
DNS Security Extensions (DNSSEC), defined in :rfc:`4033`, :rfc:`4034`,
and :rfc:`4035`. This section describes the creation and use of DNSSEC
signed zones.

In order to set up a DNSSEC secure zone, there are a series of steps
which must be followed. BIND 9 ships with several tools that are used in
this process, which are explained in more detail below. In all cases,
the ``-h`` option prints a full list of parameters. Note that the DNSSEC
tools require the keyset files to be in the working directory or the
directory specified by the ``-d`` option.

There must also be communication with the administrators of the parent
and/or child zone to transmit keys. A zone's security status must be
indicated by the parent zone for a DNSSEC-capable resolver to trust its
data. This is done through the presence or absence of a ``DS`` record at
the delegation point.

For resolvers to trust data in this zone, they must be configured with a trust
anchor. Typically this is the public key of the DNS root zone, although you
can also configure a trust anchor that is the public key of this zone or
another zone above this on in the DNS tree.

.. _dnssec_keys:

DNSSEC Keys
~~~~~~~~~~~

A secure zone must contain one or more zone keys. The zone keys
sign all other records in the zone, as well as the zone keys of any
secure delegated zones. It is recommended that zone keys use one of the
cryptographic algorithms designated as "mandatory to implement" by the
IETF, that is either RSASHA256 or ECDSAP256SHA256.

Zone keys must have the same name as the zone, have a
name type of ``ZONE``, and be usable for authentication. It is
recommended that zone keys use a cryptographic algorithm designated as
"mandatory to implement" by the IETF. Currently there are two algorithms,
RSASHA256 and ECDSAP256SHA256; ECDSAP256SHA256 is recommended for
current and future deployments.

Keys are stored in files, ``Kdnssec.example.+013+12345.key`` and
``Kdnssec.example.+013+12345.private`` (where 12345 is an example of a
key tag). The key filenames contain the key name (``dnssec.example.``),
the algorithm (5 is RSASHA1, 8 is RSASHA256, 13 is ECDSAP256SHA256, 15 is
ED25519, etc.), and the key tag (12345 in this case). The private key (in
the ``.private`` file) is used to generate signatures, and the public
key (in the ``.key`` file) is used for signature verification.

.. _dnssec_zone_signing:

Zone Signing
~~~~~~~~~~~~

To sign a zone, configure a key and signing policy for the zone. The
configuration below will sign the zone ``dnssec.example`` according to the
built-in default policy:

::

    zone "dnssec.example" {
        type primary;
        dnssec-policy default;
        file "dnssec.example.db";
    };

..

This will create the necessary keys and generates ``DNSKEY``, ``RRSIG`` and
``NSEC`` records for the zone. BIND will now also take care of any DNSSEC
maintenance for this zone, including replacing signatures that are about to
expire and managing key rollovers.

The file ``dnssec.example.db`` remains untouched and the signed zone is stored
on disk in ``dnssec.example.db.signed``. In addition to the
``Kdnssec.example.+013+12345.key`` and ``Kdnssec.example.+013+12345.private``
key files, this method stores another file on disk,
``Kdnssec.example+013+12345.state``, that tracks DNSSEC key timings and are
used to perform key rollovers safely.

The default policy creates one key that is used to sign the complete zone,
and uses ``NSEC`` to enable authenticated denial of existence (a secure way
to tell which records do not exist in your zone). How to create your own
policy is decribed in the section below.

.. _dnssec_kasp:

Key and Signing Policy
^^^^^^^^^^^^^^^^^^^^^^

A key and signing policy (KASP) is a piece of configuration that describes
how to make a zone DNSSEC secure. The built-in ``default`` policy uses the most
common DNSSEC practices, but you can define a custom policy by adding a
``dnssec-policy`` clause in your configuration:

::

    dnssec-policy "custom" {
        dnskey-ttl 600;
        keys {
            ksk lifetime PT1Y algorithm rsasha256 2048;
            zsk lifetime 60d  algorithm rsasha256 2048;
        };
    };

..

This ``custom`` policy for example, uses a short ``DNSKEY`` TTL (600 seconds)
and it uses two keys to sign the zone (a KSK to sign the key related RRsets,
``DNSKEY``, ``CDS``, and ``CDNSKEY``, and a ZSK to sign the rest of the zone).
The configured keys also have a lifetime set and use a different algorithm.

``dnssec-policy`` is described in more detail later in this document.

The :ref:`dnssec_advanced_discussions` in the DNSSEC Guide discusses the
various policy settings and may help you determining which values you should
use.

.. _dnssec_tools:

DNSSEC Tools
^^^^^^^^^^^^

There are several tools available if you want to sign your zone manually.

.. warning::

   Please note manual procedures are available mainly for backwards
   compatibility and should be used only by expert users with specific needs.

The :iscman:`dnssec-keygen` program is used to generate keys.

The following command generates an ECDSAP256SHA256 key for the
``child.example`` zone:

``dnssec-keygen -a ECDSAP256SHA256 -n ZONE child.example.``

Two output files are produced: ``Kchild.example.+013+12345.key`` and
``Kchild.example.+013+12345.private`` (where 12345 is an example of a
key tag). The key filenames contain the key name (``child.example.``),
the algorithm (5 is RSASHA1, 8 is RSASHA256, 13 is ECDSAP256SHA256, 15 is
ED25519, etc.), and the key tag (12345 in this case). The private key (in
the ``.private`` file) is used to generate signatures, and the public
key (in the ``.key`` file) is used for signature verification.

To generate another key with the same properties but with a different
key tag, repeat the above command.

The :iscman:`dnssec-keyfromlabel` program is used to get a key pair from a
crypto hardware device and build the key files. Its usage is similar to
:iscman:`dnssec-keygen`.

The public keys should be inserted into the zone file by including the
``.key`` files using ``$INCLUDE`` statements.

The :iscman:`dnssec-signzone` program is used to sign a zone.

Any ``keyset`` files corresponding to secure sub-zones should be
present. The zone signer generates ``NSEC``, ``NSEC3``, and ``RRSIG``
records for the zone, as well as ``DS`` for the child zones if
:option:`-g <dnssec-signzone -g>` is specified. If
:option:`-g <dnssec-signzone -g>` is not specified, then DS RRsets for the
secure child zones need to be added manually.

By default, all zone keys which have an available private key are used
to generate signatures. The following command signs the zone, assuming
it is in a file called ``zone.child.example``:

``dnssec-signzone -o child.example zone.child.example``

One output file is produced: ``zone.child.example.signed``. This file
should be referenced by :iscman:`named.conf` as the input file for the zone.

:iscman:`dnssec-signzone` also produces keyset and dsset files. These are used
to provide the parent zone administrators with the ``DNSKEYs`` (or their
corresponding ``DS`` records) that are the secure entry point to the zone.

.. _dnssec_config:

DNSSEC Validation
~~~~~~~~~~~~~~~~~

To enable :iscman:`named` to validate answers received from other servers, the
``dnssec-validation`` option must be set to either ``yes`` or ``auto``.

When ``dnssec-validation`` is set to ``auto``, a trust anchor for the
DNS root zone is automatically used. This trust anchor is provided
as part of BIND and is kept up to date using :rfc:`5011` key management.

When ``dnssec-validation`` is set to ``yes``, DNSSEC validation
only occurs if at least one trust anchor has been explicitly configured
in :iscman:`named.conf`, using a ``trust-anchors`` statement (or the
``managed-keys`` and ``trusted-keys`` statements, both deprecated).

When ``dnssec-validation`` is set to ``no``, DNSSEC validation does not
occur.

The default is ``auto`` unless BIND is built with
``configure --disable-auto-validation``, in which case the default is
``yes``.

The keys specified in ``trust-anchors`` are copies of ``DNSKEY`` RRs for zones
that are used to form the first link in the cryptographic chain of trust. Keys
configured with the keyword ``static-key`` or ``static-ds`` are loaded directly
into the table of trust anchors, and can only be changed by altering the
configuration. Keys configured with ``initial-key`` or ``initial-ds`` are used
to initialize :rfc:`5011` trust anchor maintenance, and are kept up-to-date
automatically after the first time :iscman:`named` runs.

``trust-anchors`` is described in more detail later in this document.

BIND 9 does not verify signatures on load, so zone keys
for authoritative zones do not need to be specified in the configuration
file.

After DNSSEC is established, a typical DNSSEC configuration looks
something like the following. It has one or more public keys for the
root, which allows answers from outside the organization to be validated.
It also has several keys for parts of the namespace that the
organization controls. These are here to ensure that :iscman:`named` is immune
to compromised security in the DNSSEC components of parent zones.

::

   trust-anchors {
       /* Root Key */
       "." initial-key 257 3 3 "BNY4wrWM1nCfJ+CXd0rVXyYmobt7sEEfK3clRbGaTwS
                    JxrGkxJWoZu6I7PzJu/E9gx4UC1zGAHlXKdE4zYIpRh
                    aBKnvcC2U9mZhkdUpd1Vso/HAdjNe8LmMlnzY3zy2Xy
                    4klWOADTPzSv9eamj8V18PHGjBLaVtYvk/ln5ZApjYg
                    hf+6fElrmLkdaz MQ2OCnACR817DF4BBa7UR/beDHyp
                    5iWTXWSi6XmoJLbG9Scqc7l70KDqlvXR3M/lUUVRbke
                    g1IPJSidmK3ZyCllh4XSKbje/45SKucHgnwU5jefMtq
                    66gKodQj+MiA21AfUVe7u99WzTLzY3qlxDhxYQQ20FQ
                    97S+LKUTpQcq27R7AT3/V5hRQxScINqwcz4jYqZD2fQ
                    dgxbcDTClU0CRBdiieyLMNzXG3";
       /* Key for our organization's forward zone */
       example.com. static-ds 54135 5 2 "8EF922C97F1D07B23134440F19682E7519ADDAE180E20B1B1EC52E7F58B2831D"

       /* Key for our reverse zone. */
       2.0.192.IN-ADDRPA.NET. static-key 257 3 5 "AQOnS4xn/IgOUpBPJ3bogzwc
                          xOdNax071L18QqZnQQQAVVr+i
                          LhGTnNGp3HoWQLUIzKrJVZ3zg
                          gy3WwNT6kZo6c0tszYqbtvchm
                          gQC8CzKojM/W16i6MG/eafGU3
                          siaOdS0yOI6BgPsw+YZdzlYMa
                          IJGf4M4dyoKIhzdZyQ2bYQrjy
                          Q4LB0lC7aOnsMyYKHHYeRvPxj
                          IQXmdqgOJGq+vsevG06zW+1xg
                          YJh9rCIfnm1GX/KMgxLPG2vXT
                          D/RnLX+D3T3UL7HJYHJhAZD5L
                          59VvjSPsZJHeDCUyWYrvPZesZ
                          DIRvhDD52SKvbheeTJUm6Ehkz
                          ytNN2SN96QRk8j/iI8ib";
   };

   options {
       ...
       dnssec-validation yes;
   };

..

.. note::

   None of the keys listed in this example are valid. In particular, the
   root key is not valid.

When DNSSEC validation is enabled and properly configured, the resolver
rejects any answers from signed, secure zones which fail to
validate, and returns SERVFAIL to the client.

Responses may fail to validate for any of several reasons, including
missing, expired, or invalid signatures, a key which does not match the
DS RRset in the parent zone, or an insecure response from a zone which,
according to its parent, should have been secure.

.. note::

   When the validator receives a response from an unsigned zone that has
   a signed parent, it must confirm with the parent that the zone was
   intentionally left unsigned. It does this by verifying, via signed
   and validated NSEC/NSEC3 records, that the parent zone contains no DS
   records for the child.

   If the validator *can* prove that the zone is insecure, then the
   response is accepted. However, if it cannot, the validator must assume an
   insecure response to be a forgery; it rejects the response and logs
   an error.

   The logged error reads "insecurity proof failed" and "got insecure
   response; parent indicates it should be secure."


.. _dnssec_dynamic_zones:

DNSSEC, Dynamic Zones, and Automatic Signing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Converting From Insecure to Secure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A zone can be changed from insecure to secure in three ways: using a
dynamic DNS update, via the ``auto-dnssec`` zone option, or by setting a
DNSSEC policy for the zone with ``dnssec-policy``.

For any method, :iscman:`named` must be configured so that it can see
the ``K*`` files which contain the public and private parts of the keys
that are used to sign the zone. These files are generated
by :iscman:`dnssec-keygen`, or created when needed by :iscman:`named` if
``dnssec-policy`` is used. Keys should be placed in the
key-directory, as specified in :iscman:`named.conf`:

::

       zone example.net {
           type primary;
           update-policy local;
           file "dynamic/example.net/example.net";
           key-directory "dynamic/example.net";
       };

If one KSK and one ZSK DNSKEY key have been generated, this
configuration causes all records in the zone to be signed with the
ZSK, and the DNSKEY RRset to be signed with the KSK. An NSEC
chain is generated as part of the initial signing process.

With ``dnssec-policy``, it is possible to specify which keys should be
KSK and/or ZSK. To sign all records with a key, a CSK must be specified.
For example:

::

        dnssec-policy csk {
	    keys {
                csk lifetime unlimited algorithm 13;
            };
	};

Dynamic DNS Update Method
^^^^^^^^^^^^^^^^^^^^^^^^^

To insert the keys via dynamic update:

::

       % nsupdate
       > ttl 3600
       > update add example.net DNSKEY 256 3 7 AwEAAZn17pUF0KpbPA2c7Gz76Vb18v0teKT3EyAGfBfL8eQ8al35zz3Y I1m/SAQBxIqMfLtIwqWPdgthsu36azGQAX8=
       > update add example.net DNSKEY 257 3 7 AwEAAd/7odU/64o2LGsifbLtQmtO8dFDtTAZXSX2+X3e/UNlq9IHq3Y0 XtC0Iuawl/qkaKVxXe2lo8Ct+dM6UehyCqk=
       > send

While the update request completes almost immediately, the zone is
not completely signed until :iscman:`named` has had time to "walk" the zone
and generate the NSEC and RRSIG records. The NSEC record at the apex
is added last, to signal that there is a complete NSEC chain.

To sign using :ref:`NSEC3 <advanced_discussions_nsec3>` instead of :ref:`NSEC
<advanced_discussions_nsec>`, add an NSEC3PARAM record to the initial update
request. The :term:`OPTOUT <opt-out>` bit in the NSEC3
chain can be set in the flags field of the
NSEC3PARAM record.

::

       % nsupdate
       > ttl 3600
       > update add example.net DNSKEY 256 3 7 AwEAAZn17pUF0KpbPA2c7Gz76Vb18v0teKT3EyAGfBfL8eQ8al35zz3Y I1m/SAQBxIqMfLtIwqWPdgthsu36azGQAX8=
       > update add example.net DNSKEY 257 3 7 AwEAAd/7odU/64o2LGsifbLtQmtO8dFDtTAZXSX2+X3e/UNlq9IHq3Y0 XtC0Iuawl/qkaKVxXe2lo8Ct+dM6UehyCqk=
       > update add example.net NSEC3PARAM 1 1 100 1234567890
       > send

Again, this update request completes almost immediately; however,
the record does not show up until :iscman:`named` has had a chance to
build/remove the relevant chain. A private type record is created
to record the state of the operation (see below for more details), and
is removed once the operation completes.

While the initial signing and NSEC/NSEC3 chain generation is happening,
other updates are possible as well.

Fully Automatic Zone Signing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To enable automatic signing, set a ``dnssec-policy`` or add the
``auto-dnssec`` option to the zone statement in :iscman:`named.conf`.
``auto-dnssec`` has two possible arguments: ``allow`` or ``maintain``.

With ``auto-dnssec allow``, :iscman:`named` can search the key directory for
keys matching the zone, insert them into the zone, and use them to sign
the zone. It does so only when it receives an
:option:`rndc sign zonename <rndc sign>`.

``auto-dnssec maintain`` includes the above functionality, but also
automatically adjusts the zone's DNSKEY records on a schedule according to
the keys' timing metadata. (See :ref:`man_dnssec-keygen` and
:ref:`man_dnssec-settime` for more information.)

``dnssec-policy`` is similar to ``auto-dnssec maintain``, but
``dnssec-policy`` also automatically creates new keys when necessary. In
addition, any configuration related to DNSSEC signing is retrieved from the
policy, ignoring existing DNSSEC :iscman:`named.conf` options.

:iscman:`named` periodically searches the key directory for keys matching
the zone; if the keys' metadata indicates that any change should be
made to the zone - such as adding, removing, or revoking a key - then that
action is carried out. By default, the key directory is checked for
changes every 60 minutes; this period can be adjusted with
``dnssec-loadkeys-interval``, up to a maximum of 24 hours. The
:option:`rndc loadkeys` command forces :iscman:`named` to check for key updates immediately.

If keys are present in the key directory the first time the zone is
loaded, the zone is signed immediately, without waiting for an
:option:`rndc sign` or :option:`rndc loadkeys` command. Those commands can still be
used when there are unscheduled key changes.

When new keys are added to a zone, the TTL is set to match that of any
existing DNSKEY RRset. If there is no existing DNSKEY RRset, the
TTL is set to the TTL specified when the key was created (using the
:option:`dnssec-keygen -L` option), if any, or to the SOA TTL.

To sign the zone using NSEC3 instead of NSEC, submit an
NSEC3PARAM record via dynamic update prior to the scheduled publication
and activation of the keys. The OPTOUT bit for the NSEC3 chain can be set
in the flags field of the NSEC3PARAM record. The
NSEC3PARAM record does not appear in the zone immediately, but it is
stored for later reference. When the zone is signed and the NSEC3
chain is completed, the NSEC3PARAM record appears in the zone.

Using the ``auto-dnssec`` option requires the zone to be configured to
allow dynamic updates, by adding an ``allow-update`` or
``update-policy`` statement to the zone configuration. If this has not
been done, the configuration fails.

Private Type Records
^^^^^^^^^^^^^^^^^^^^

The state of the signing process is signaled by private type records
(with a default type value of 65534). When signing is complete, those
records with a non-zero initial octet have a non-zero value for the final octet.

If the first octet of a private type record is non-zero, the
record indicates either that the zone needs to be signed with the key matching
the record, or that all signatures that match the record should be
removed. Here are the meanings of the different values of the first octet:

   - algorithm (octet 1)

   - key id in network order (octet 2 and 3)

   - removal flag (octet 4)
   
   - complete flag (octet 5)

Only records flagged as "complete" can be removed via dynamic update; attempts
to remove other private type records are silently ignored.

If the first octet is zero (this is a reserved algorithm number that
should never appear in a DNSKEY record), the record indicates that
changes to the NSEC3 chains are in progress. The rest of the record
contains an NSEC3PARAM record, while the flag field tells what operation to
perform based on the flag bits:

   0x01 OPTOUT

   0x80 CREATE

   0x40 REMOVE

   0x20 NONSEC

DNSKEY Rollovers
^^^^^^^^^^^^^^^^

As with insecure-to-secure conversions, DNSSEC keyrolls can be done
in two ways: using a dynamic DNS update, or via the ``auto-dnssec`` zone
option.

Dynamic DNS Update Method
^^^^^^^^^^^^^^^^^^^^^^^^^

To perform key rollovers via a dynamic update, the ``K*``
files for the new keys must be added so that :iscman:`named` can find them.
The new DNSKEY RRs can then be added via dynamic update. :iscman:`named` then causes the
zone to be signed with the new keys; when the signing is complete, the
private type records are updated so that the last octet is non-zero.

If this is for a KSK, the parent and any trust anchor
repositories of the new KSK must be informed.

The maximum TTL in the zone must expire before removing the
old DNSKEY. If it is a KSK that is being updated,
the DS RRset in the parent must also be updated and its TTL allowed to expire. This
ensures that all clients are able to verify at least one signature
when the old DNSKEY is removed.

The old DNSKEY can be removed via UPDATE, taking care to specify the
correct key. :iscman:`named` cleans out any signatures generated by the
old key after the update completes.

Automatic Key Rollovers
^^^^^^^^^^^^^^^^^^^^^^^

When a new key reaches its activation date (as set by :iscman:`dnssec-keygen`
or :iscman:`dnssec-settime`), and if the ``auto-dnssec`` zone option is set to
``maintain``, :iscman:`named` automatically carries out the key rollover.
If the key's algorithm has not previously been used to sign the zone,
then the zone is fully signed as quickly as possible. However, if
the new key replaces an existing key of the same algorithm, the
zone is re-signed incrementally, with signatures from the old key
replaced with signatures from the new key as their signature
validity periods expire. By default, this rollover completes in 30 days,
after which it is safe to remove the old key from the DNSKEY RRset.

NSEC3PARAM Rollovers via UPDATE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The new NSEC3PARAM record can be added via dynamic update. When the new NSEC3
chain has been generated, the NSEC3PARAM flag field is set to zero. At
that point, the old NSEC3PARAM record can be removed. The old chain is
removed after the update request completes.

Converting From NSEC to NSEC3
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add a ``nsec3param`` option to your ``dnssec-policy`` and
run :option:`rndc reconfig`.

Or use :iscman:`nsupdate` to add an NSEC3PARAM record.

In both cases, the NSEC3 chain is generated and the NSEC3PARAM record is
added before the NSEC chain is destroyed.

Converting From NSEC3 to NSEC
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To do this, remove the ``nsec3param`` option from the ``dnssec-policy`` and
run :option:`rndc reconfig`.

Or use :iscman:`nsupdate` to remove all NSEC3PARAM records with a
zero flag field. The NSEC chain is generated before the NSEC3 chain
is removed.

Converting From Secure to Insecure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To convert a signed zone to unsigned using dynamic DNS, delete all the
DNSKEY records from the zone apex using :iscman:`nsupdate`. All signatures,
NSEC or NSEC3 chains, and associated NSEC3PARAM records are removed
automatically. This takes place after the update request completes.

This requires the ``dnssec-secure-to-insecure`` option to be set to
``yes`` in :iscman:`named.conf`.

In addition, if the ``auto-dnssec maintain`` zone statement is used, it
should be removed or changed to ``allow`` instead; otherwise it will re-sign.

Periodic Re-signing
^^^^^^^^^^^^^^^^^^^

In any secure zone which supports dynamic updates, :iscman:`named`
periodically re-signs RRsets which have not been re-signed as a result of
some update action. The signature lifetimes are adjusted to
spread the re-sign load over time rather than all at once.

NSEC3 and OPTOUT
^^^^^^^^^^^^^^^^

:iscman:`named` only supports creating new NSEC3 chains where all the NSEC3
records in the zone have the same OPTOUT state. :iscman:`named` supports
UPDATES to zones where the NSEC3 records in the chain have mixed OPTOUT
state. :iscman:`named` does not support changing the OPTOUT state of an
individual NSEC3 record; if the
OPTOUT state of an individual NSEC3 needs to be changed, the entire chain must be changed.
