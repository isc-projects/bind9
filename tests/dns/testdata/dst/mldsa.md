The ML-DSA-44 key and signature are the example from Section 6 of
[draft-westerbaan-dnssec-mldsa-04](https://www.ietf.org/archive/id/draft-westerbaan-dnssec-mldsa-04.html#section-6).
The private key is the 32-byte seed 00, 01, ..., 1f. The public key's key tag
is 59829. `mldsa.sig` is the hex encoding of the published signature, and
`mldsa.data` is the RFC 4034 Section 3.1.8.1 wire encoding of the example's
RRSIG fields and MX RRset. No signature is regenerated for this fixture.

These four test-vector files are Copyright (c) 2026 IETF Trust and the
persons identified as the document authors. All rights reserved. They are
provided under the [Revised BSD License](../../../../LICENSES/BSD-3-Clause.txt).
