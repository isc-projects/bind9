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

.. _pkcs11:

PKCS#11 (Cryptoki) Support
~~~~~~~~~~~~~~~~~~~~~~~~~~

Public Key Cryptography Standard #11 (PKCS#11) defines a
platform-independent API for the control of hardware security modules
(HSMs) and other cryptographic support devices.

PKCS#11 uses a "provider library": a dynamically loadable
library which provides a low-level PKCS#11 interface to drive the HSM
hardware. The PKCS#11 provider library comes from the HSM vendor, and it
is specific to the HSM to be controlled.

BIND 9 accesses PKCS#11 libraries via OpenSSL Providers. The provider for
OpenSSL 3 and newer is `pkcs11-provider`_.

.. _`pkcs11-provider`: https://github.com/latchset/pkcs11-provider

In both cases the extension is dynamically loaded into OpenSSL and the HSM is
operated indirectly; any cryptographic operations not supported by the HSM can
be carried out by OpenSSL instead.

Prerequisites
^^^^^^^^^^^^^

See the documentation provided by the HSM vendor for information about
installing, initializing, testing, and troubleshooting the HSM.

Building SoftHSMv2
^^^^^^^^^^^^^^^^^^

SoftHSMv2, the latest development version of SoftHSM, is available from
https://github.com/softhsm/SoftHSMv2. It is a software library
developed by the OpenDNSSEC project (https://www.opendnssec.org) which
provides a PKCS#11 interface to a virtual HSM, implemented in the form
of an SQLite3 database on the local filesystem. It provides less security
than a true HSM, but it allows users to experiment with native PKCS#11
when an HSM is not available. SoftHSMv2 can be configured to use either
OpenSSL or the Botan library to perform cryptographic functions, but
when using it for native PKCS#11 in BIND, OpenSSL is required.

By default, the SoftHSMv2 configuration file is ``prefix/etc/softhsm2.conf``
(where ``prefix`` is configured at compile time). This location can be
overridden by the SOFTHSM2_CONF environment variable. The SoftHSMv2
cryptographic store must be installed and initialized before using it
with BIND.

::

   $  cd SoftHSMv2
   $  configure --with-crypto-backend=openssl --prefix=/opt/pkcs11/usr
   $  make
   $  make install
   $  /opt/pkcs11/usr/bin/softhsm-util --init-token 0 --slot 0 --label softhsmv2

OpenSSL 3 With pkcs11-provider
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

OpenSSL provider-based PKCS#11 uses the pkcs11-provider project.

pkcs11-provider tries to fit the PKCS#11 API within the Provider API of OpenSSL;
that is, it provides a gateway between PKCS#11 modules and the OpenSSL Provider
API. The provider must be registered with OpenSSL and the
path to the PKCS#11 module gateway must be provided. This can be done by
editing the OpenSSL configuration file, by provider-specific controls, or by using
the p11-kit proxy module.

It is required to use pkcs11-provider version 0.3 or later.  It is recommended
to use the lastest version available.

Configuring pkcs11-provider
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The canonical documentation for configuring pkcs11-provider is in the
`provider-pkcs11.7`_ manual page, but a copy of a working configuration is
provided here for convenience:

.. _`provider-pkcs11.7`: https://github.com/latchset/pkcs11-provider/blob/main/docs/provider-pkcs11.7.md

In this example, we use a custom copy of OpenSSL configuration,
driven by an environment variable called OPENSSL_CONF. First, copy the
global OpenSSL configuration (often found in
``etc/ssl/openssl.conf``) and customize it to use pkcs11-provider.

::

   cp /etc/ssl/openssl.cnf /opt/bind9/etc/openssl.cnf

Next, export the environment variable:

::

   export OPENSSL_CONF=/opt/bind9/etc/openssl.cnf

Then add the following line at the top of the file, before any sections (in square
brackets) are defined:

::

   openssl_conf = openssl_init

Make sure there are no other 'openssl_conf = ...' lines in the file.

Add the following lines at the bottom of the file:

::

   [openssl_init]
   providers = provider_init

   [provider_init]
   default = default_init
   pkcs11 = pkcs11_init

   [default_init]
   activate = 1

   [pkcs11_init]
   module = <PATHTO>/pkcs11.so
   pkcs11-module-path = <FULL_PATH_TO_HSM_MODULE>
   # bind uses the digest+sign api. this is broken with the default load behaviour,
   # but works with early load. see: https://github.com/latchset/pkcs11-provider/issues/266
   pkcs11-module-load-behavior = early
   # no-deinit quirk is needed if you use softhsm2
   #pkcs11-module-quirks = no-deinit
   # if automatic logging to the token is needed, PIN can be specified as below
   # the file referenced should contain just the PIN
   #pkcs11-module-token-pin = file:/etc/pki/pin.txt
   activate = 1

Key Generation
^^^^^^^^^^^^^^

HSM keys can now be created and used.  We are assuming that
BIND 9 is already installed, either from a package or from the sources, and the
tools are readily available in the ``$PATH``.

A zone that is configured with ``dnssec-policy`` can generate keys through
the PKCS#11 Provider API of OpenSSL.

If you want to create keys manually, the ``pkcs11-tool`` available from the
`OpenSC`_ suite can be used. On both DEB-based and RPM-based distributions,
the package is called opensc.

.. _OpenSC: https://github.com/OpenSC/libp11

We need to generate at least two RSA keys:

::

   pkcs11-tool --module <FULL_PATH_TO_HSM_MODULE> -l -k --key-type rsa:2048 --label example.net-ksk --pin <PIN>
   pkcs11-tool --module <FULL_PATH_TO_HSM_MODULE> -l -k --key-type rsa:2048 --label example.net-zsk --pin <PIN>

Remember that each key should have unique label and we are going to use that
label to reference the private key.

Convert the RSA keys stored in the HSM into a format that BIND 9 understands.
The :iscman:`dnssec-keyfromlabel` tool from BIND 9 can link the raw keys stored in the
HSM with the ``K<zone>+<alg>+<id>`` files.

The algorithm (``RSASHA256``) must be provided. The key is referenced with
the PKCS#11 URI scheme and it can contain the PKCS#11 token label (we asume that
it has been initialized as bind9), and the PKCS#11 object label (called label
when generating the keys using ``pkcs11-tool``) and the HSM PIN. Refer to
:rfc:`7512` for the full PKCS#11 URI specification.

Convert the KSK:

::

   dnssec-keyfromlabel -a RSASHA256 -l "pkcs11:token=bind9;object=example.net-ksk;pin-value=0000" -f KSK example.net

and ZSK:

::

   dnssec-keyfromlabel -a RSASHA256 -l "pkcs11:token=bind9;object=example.net-zsk;pin-value=0000" example.net

NOTE: a PIN stored on disk can be used by specifying ``pin-source=<path_to>/<file>``, e.g:

::

   (umask 0700 && echo -n 0000 > /opt/bind9/etc/pin.txt)

and then use in the label specification:

::

   pin-source=/opt/bind9/etc/pin.txt

Confirm that there is one KSK and one ZSK present in the current directory:

::

   ls -l K*

The output should look like this (the second number will be different):

::

   Kexample.net.+008+31729.key
   Kexample.net.+008+31729.private
   Kexample.net.+008+42231.key
   Kexample.net.+008+42231.private

A note on generating ECDSA keys: there is a bug in libp11 when looking up a key.
That function compares keys only on their ID, not the label, so when looking up
a key it returns the first key, rather than the matching key. To work around
this when creating ECDSA keys, specify a unique ID:

::

   ksk=$(echo "example.net-ksk" | openssl sha1 -r | awk '{print $1}')
   zsk=$(echo "example.net-zsk" | openssl sha1 -r | awk '{print $1}')
   pkcs11-tool --module <FULL_PATH_TO_HSM_MODULE> -l -k --key-type EC:prime256v1 --id $ksk --label example.net-ksk --pin <PIN>
   pkcs11-tool --module <FULL_PATH_TO_HSM_MODULE> -l -k --key-type EC:prime256v1 --id $zsk --label example.net-zsk --pin <PIN>


Running :iscman:`named` With Automatic Zone Re-signing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once the keys are created, the zone can also be signed automatically by named
without further requisites.

The logs should have lines like:

::

   Fetching example.net/RSASHA256/31729 (KSK) from key repository.
   DNSKEY example.net/RSASHA256/31729 (KSK) is now published
   DNSKEY example.net/RSA256SHA256/31729 (KSK) is now active
   Fetching example.net/RSASHA256/42231 (ZSK) from key repository.
   DNSKEY example.net/RSASHA256/42231 (ZSK) is now published
   DNSKEY example.net/RSA256SHA256/42231 (ZSK) is now active

For :iscman:`named` to dynamically re-sign zones using HSM keys,
and/or to sign new records inserted via nsupdate, :iscman:`named` must
have access to the HSM PIN. In OpenSSL-based PKCS#11, this is
accomplished by placing the PIN into the ``openssl.cnf`` file (in the above
examples, ``/opt/pkcs11/usr/ssl/openssl.cnf``).

See OpenSSL extension-specific documentation for instructions on configuring the PIN on
the global level; doing so allows the ``dnssec-\*`` tools to access the HSM without
PIN entry. (The ``pkcs11-\*`` tools access the HSM directly, not via OpenSSL,
so a PIN is still required to use them.)
