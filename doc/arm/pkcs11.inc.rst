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

BIND 9 access PKCS#11 libraries via OpenSSL extensions. The extension for
OpenSSL 3 and newer is `pkcs11-provider`_. And for the older OpenSSL versions
engine_pkcs11 from the `OpenSC`_ project can be used.

.. _`pkcs11-provider`: https://github.com/latchset/pkcs11-provider
.. _OpenSC: https://github.com/OpenSC/libp11

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
https://github.com/opendnssec/SoftHSMv2. It is a software library
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

OpenSSL 1.x.x with engine_pkcs11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

OpenSSL engine-based PKCS#11 uses engine_pkcs11 OpenSSL engine from libp11 project.

engine_pkcs11 tries to fit the PKCS#11 API within the engine API of OpenSSL.
That is, it provides a gateway between PKCS#11 modules and the OpenSSL engine
API.  One has to register the engine with OpenSSL and one has to provide the
path to the PKCS#11 module which should be gatewayed to. This can be done by
editing the OpenSSL configuration file, by engine specific controls, or by using
the p11-kit proxy module.

It is recommended, that libp11 >= 0.4.12 is used.

For more detailed howto including the examples, we recommend reading:

https://gitlab.isc.org/isc-projects/bind9/-/wikis/BIND-9-PKCS11

When using engine_pkcs11, all BIND binaries potentially need the keys require
'-E pkcs11' argument to activate the engine support.

Even though OpenSSL 3 has compatibility support for Engine API it is not
recommended to be used due to bugs in OpenSSL and libp11.

Configuring engine_pkcs11
^^^^^^^^^^^^^^^^^^^^^^^^^

The canonical documentation for configuring engine_pkcs11 is in the
`libp11/README.md`_, but here's copy of working configuration for
your convenience:

.. _`libp11/README.md`: https://github.com/OpenSC/libp11/blob/master/README.md#pkcs-11-module-configuration

We are going to use our own custom copy of OpenSSL configuration, again it's
driven by an environment variable, this time called OPENSSL_CONF.  We are
going to copy the global OpenSSL configuration (often found in
``etc/ssl/openssl.conf``) and customize it to use engines_pkcs11.

::

   cp /etc/ssl/openssl.cnf /opt/bind9/etc/openssl.cnf

and export the environment variable:

::

   export OPENSSL_CONF=/opt/bind9/etc/openssl.cnf

Now add the following line at the top of file, before any sections (in square
brackets) are defined:

::

   openssl_conf = openssl_init

And make sure there are no other 'openssl_conf = ...' lines in the file.

Add following lines at the bottom of the file:

::

   [openssl_init]
   engines=engine_section

   [engine_section]
   pkcs11 = pkcs11_section

   [pkcs11_section]
   engine_id = pkcs11
   dynamic_path = <PATHTO>/pkcs11.so
   MODULE_PATH = <FULL_PATH_TO_HSM_MODULE>
   # if automatic logging to the token is needed, PIN can be specified as below
   #PIN = 1234
   init = 0

Enabling the OpenSSL Engine in BIND commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using OpenSSL Engine-based PKCS#11, the "engine" to be used by OpenSSL can be
specified in :iscman:`named` and all of the BIND ``dnssec-*`` tools by using the ``-E
<engine>`` command line option. This engine name matches the 'engine_id' in the
``openssl.cnf`` created in previous section.

The zone signing commences as usual, with only one small difference.  We need to
provide the name of the OpenSSL engine using the -E command line option.

::

   dnssec-signzone -E pkcs11 -S -o example.net example.net


OpenSSL 3 with pkcs11-provider
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

OpenSSL provider-based PKCS#11 uses pkcs11-provider project.

pkcs11-provider tries to fit the PKCS#11 API within the Provider API of OpenSSL.
That is, it provides a gateway between PKCS#11 modules and the OpenSSL Provider
API.  One has to register the engine with OpenSSL and one has to provide the
path to the PKCS#11 module which should be gatewayed to. This can be done by
editing the OpenSSL configuration file, by engine specific controls, or by using
the p11-kit proxy module.

It is recommended that pkcs11-provider git commit 8672b98d2558aecb49f173df97b1463c7697b540
from August 15, 2023 or later is used.

BIND support for pkcs11-provider is built in and the -E command line option
explained above should not be used.

Configuring pkcs11-provider
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The canonical documentation for configuring pkcs11-provider is in the
`provider-pkcs11.7`_ manual page, but here's copy of working configuration for
your convenience:

.. _`provider-pkcs11.7`: https://github.com/latchset/pkcs11-provider/blob/main/docs/provider-pkcs11.7.md

We are going to use our own custom copy of OpenSSL configuration, again it's
driven by an environment variable, this time called OPENSSL_CONF.  We are
going to copy the global OpenSSL configuration (often found in
``etc/ssl/openssl.conf``) and customize it to use pkcs11-provider.

::

   cp /etc/ssl/openssl.cnf /opt/bind9/etc/openssl.cnf

and export the environment variable:

::

   export OPENSSL_CONF=/opt/bind9/etc/openssl.cnf

Now add the following line at the top of file, before any sections (in square
brackets) are defined:

::

   openssl_conf = openssl_init

And make sure there are no other 'openssl_conf = ...' lines in the file.

Add following lines at the bottom of the file:

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

HSM keys can now be created and used.  We are going to assume that you already
have a BIND 9 installed, either from a package, or from the sources, and the
tools are readily available in the ``$PATH``.

For generating the keys, we are going to use ``pkcs11-tool`` available from the
OpenSC suite.  On both DEB-based and RPM-based distributions, the package is
called opensc.

We need to generate at least two RSA keys:

::

   pkcs11-tool --module <FULL_PATH_TO_HSM_MODULE> -l -k --key-type rsa:2048 --label example.net-ksk --pin <PIN>
   pkcs11-tool --module <FULL_PATH_TO_HSM_MODULE> -l -k --key-type rsa:2048 --label example.net-zsk --pin <PIN>

Remember that each key should have unique label and we are going to use that
label to reference the private key.

Convert the RSA keys stored in the HSM into a format that BIND 9 understands.
The :iscman:`dnssec-keyfromlabel` tool from BIND 9 can link the raw keys stored in the
HSM with the ``K<zone>+<alg>+<id>`` files.

You'll need to provide the OpenSSL engine name (``pkcs11``) if using the engine and
the algorithm (``RSASHA256``). The key is referenced with the PKCS#11 URI scheme and it
can contain the PKCS#11 token label (we asume that it has been initialized as bind9),
and the PKCS#11 object label (called label when generating the keys using ``pkcs11-tool``)
and the HSM PIN. Refer to `RFC7512`_ for the full PKCS#11 URI specification.

.. _`RFC7512`: https://www.rfc-editor.org/rfc/rfc7512.html

Convert the KSK:

::

   dnssec-keyfromlabel -E pkcs11 -a RSASHA256 -l "pkcs11:token=bind9;object=example.net-ksk;pin-value=0000" -f KSK example.net

and ZSK:

::

   dnssec-keyfromlabel -E pkcs11 -a RSASHA256 -l "pkcs11:token=bind9;object=example.net-zsk;pin-value=0000" example.net

NOTE: you can use PIN stored on disk, by specifying ``pin-source=<path_to>/<file>``, f.e.:

::

   (umask 0700 && echo -n 0000 > /opt/bind9/etc/pin.txt)

and then use in the label specification:

::

   pin-source=/opt/bind9/etc/pin.txt

Confirm that you have one KSK and one ZSK present in the current directory:

::

   ls -l K*

The output should look like this (the second number will be different):

::

   Kexample.net.+008+31729.key
   Kexample.net.+008+31729.private
   Kexample.net.+008+42231.key
   Kexample.net.+008+42231.private

A note on generating ECDSA keys: there is a bug in libp11 when looking up a key,
that function compares keys only on their ID, not the label. So when looking up
a key it returns the first key, rather than the matching key. The workaround for
this is when creating ECDSA keys, you should specify a unique ID:

::

   ksk=$(echo "example.net-ksk" | openssl sha1 -r | awk '{print $1}')
   zsk=$(echo "example.net-zsk" | openssl sha1 -r | awk '{print $1}')
   pkcs11-tool --module <FULL_PATH_TO_HSM_MODULE> -l -k --key-type EC:prime256v1 --id $ksk --label example.net-ksk --pin <PIN>
   pkcs11-tool --module <FULL_PATH_TO_HSM_MODULE> -l -k --key-type EC:prime256v1 --id $zsk --label example.net-zsk --pin <PIN>


Running :iscman:`named` With Automatic Zone Re-signing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The zone can also be signed automatically by named. Again, we need to provide
the name of the OpenSSL engine using the :option:`-E <named -E>` command line option,
if using OpenSSL 1.x.x with engine_pkcs11, and this is not needed when using OpenSSL 3.x.x providers.

::

   named -E pkcs11 -c named.conf

and the logs should have lines like:

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

See OpenSSL extension specific documentation on how to configure the PIN on
global level. Doing so allows the ``dnssec-\*`` tools to access the HSM without
PIN entry. (The ``pkcs11-\*`` tools access the HSM directly, not via OpenSSL,
so a PIN is still required to use them.)
