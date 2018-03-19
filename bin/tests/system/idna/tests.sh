# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

# This set of tests check the behavior of the IDNA options in "dig".
#
# "dig" supports two IDNA-related options:
#
# +[no]idnin -  Translates a domain name into punycode format before sending
#               the query to the server.
# +[no]idnout - Translates the received punycode domain names into appropriate
#               unicode characters before displaying.
#
# The tests run "dig" against an authoritative server configured with a minimal
# root zone and nothing else.  As a result, all queries will result in an
# NXDOMAIN.  The server will return the qname sent, which "dig" will display
# according to the options selected.  This returned string is compared with
# the qname originally sent.
#
# In the comments below, the following nomenclature (taken from RFC 5890) is
# used:
#
# A-label: Label comprising ASCII characters that starts xn-- and whose
#          characters after the xn-- are a valid output of the Punycode
#          algorithm.
#
# Fake A-label: An A-label whose characters after the xn-- are not valid
#          Punycode output.
#
# U-label: Unicode (native character) form of a label.
#
# For the purpose of this test script, U-labels do not include labels that
# comprise purely ASCII characters, which are referred to as "ASCII-labels"
# here. Valid ASCII-labels comprise letters, digits and hyphens and do not
# start with a hyphen.
#
# References:
# 1. http://www.unicode.org/reports/tr46/#Deviations
# 2. http://www.unicode.org/reports/tr46/#IDNAComparison

# Using dig insecure mode as we are not testing DNSSEC here
DIGCMD="$DIG -i -p ${PORT} @10.53.0.1"

# Initialize test count and status return
n=0
status=0


# Function for extracting the question name reported by "dig".
#
# This is the first field after the line starting ";; QUESTION SECTION:".
# The string returned includes the trailing period.

qname() {
    awk 'BEGIN { qs = 0; } \
        /;; QUESTION SECTION:/ { qs = 1; next; } \
        qs == 1 {sub(";", "", $1) ; print $1; exit 0; }' \
        $1
}

# Function for performing the test where "dig" is expected to succeed.
#
#   $1 - Description of the test
#   $2 - Dig command additional options
#   $3 - Name being queried
#   $4 - The name that should be displayed by "dig".  Note that names displayed
#        by "dig" will always have a trailing period, so this parameter should
#        have that period as well.

idna_test() {
    n=`expr $n + 1`
    description=$1
    if [ "$2" != "" ]; then
        description="${description}: $2"
    fi
    echo_i "$description ($n)"

    ret=0
    $DIGCMD $2 $3 > dig.out.$n 2>&1
    if [ $? -ne 0 ]; then
        echo_i "failed: dig returned error status $?"
        ret=1
    else
        actual=`qname dig.out.$n`
        if [ "$4" != "$actual" ]; then
            echo_i "failed: expected answer $4, actual result $actual"
            ret=1
        fi
    fi
    status=`expr $status + $ret`
}

# Function for performing test where "dig" is expected to fail
#
# $1 - $3: As for idna_test function

idna_fail() {
    n=`expr $n + 1`
    description=$1
    if [ "$2" != "" ]; then
        description="${description}: $2"
    fi
    echo_i "$description ($n)"

    ret=0
    $DIGCMD $2 $3 > dig.out.$n 2>&1
    if [ $? -eq 0 ]; then
        echo_i "failed: dig command unexpectedly succeeded"
        ret=1
    fi
    status=`expr $status + $ret`
}

# Tests of valid ASCII-label.
#
# +noidnin: The label is sent unchanged to the server.
# +idnin:   The label is lower-cased and sent to the server.
#
# The +[no]idnout flag has no effect on the result.

text="Checking valid ASCII label"
idna_test "$text" ""                   LocalhosT localhost.
idna_test "$text" "+noidnin +noidnout" LocalhosT LocalhosT.
idna_test "$text" "+noidnin +idnout"   LocalhosT LocalhosT.
idna_test "$text" "+idnin   +noidnout" LocalhosT localhost.
idna_test "$text" "+idnin   +idnout"   LocalhosT localhost.



# Tests of a valid U-label.
#
# +noidnin +noidnout: The label is sent as a unicode octet stream and dig will
#                     display the string in the \nnn format.
# +noidnin +idnout:   As for the previous case.
# +idnin   +noidnout: The label is converted to the xn-- format.  "dig"
#                     displays the returned xn-- text.
# +idnin   +idnout:   The label is converted to the xn-- format.  "dig"
#                     converts the returned xn-- string back to the original
#                     unicode text.
#
# Note that ASCII characters are converted to lower-case.

text="Checking valid non-ASCII label"
idna_test "$text" ""                   "München" "münchen." 
idna_test "$text" "+noidnin +noidnout" "München" "M\195\188nchen."
idna_test "$text" "+noidnin +idnout"   "München" "M\195\188nchen."
idna_test "$text" "+idnin   +noidnout" "München" "xn--mnchen-3ya."
idna_test "$text" "+idnin   +idnout"   "München" "münchen." 



# Tests of transitional processing of a valid U-label
#
# IDNA2003 introduced national character sets but, unfortunately, didn't
# support several characters properly.  One of those was the German character
# "ß" (the "Eszett" or "sharp s"), which was interpreted as "ss".  So the
# domain “faß.de” domain (for example) was processed as “fass.de”.
#
# This was corrected in IDNA2008, although some vendors that adopted this
# standard chose to keep the existing IDNA2003 translation for this character
# to prevent problems (e.g. people visiting www.faß.example would, under
# IDNA2003, go to www.fass.example but under IDNA2008 would end up at
# www.fa\195\159.example - a different web site).
#
# BIND has adopted a hard transition, so this test checks that the transitional
# mapping is not used.  The tests are essentially the same as for the valid
# U-label.

text="Checking that non-transitional IDNA processing is used"
idna_test "$text" ""                   "faß.de" "faß.de."
idna_test "$text" "+noidnin +noidnout" "faß.de" "fa\195\159.de."
idna_test "$text" "+noidnin +idnout"   "faß.de" "fa\195\159.de."
idna_test "$text" "+idnin   +noidnout" "faß.de" "xn--fa-hia.de."
idna_test "$text" "+idnin   +idnout"   "faß.de" "faß.de."

# Another problem character.  The final character in the first label mapped
# onto the Greek sigma character ("σ") in IDNA2003.

text="Second check that non-transitional IDNA processing is used"
idna_test "$text" ""                   "βόλος.com" "βόλος.com." 
idna_test "$text" "+noidnin +noidnout" "βόλος.com" "\206\178\207\140\206\187\206\191\207\130.com."
idna_test "$text" "+noidnin +idnout"   "βόλος.com" "\206\178\207\140\206\187\206\191\207\130.com."
idna_test "$text" "+idnin   +noidnout" "βόλος.com" "xn--nxasmm1c.com."
idna_test "$text" "+idnin   +idnout"   "βόλος.com" "βόλος.com." 



# Tests of a valid A-label (i.e. starting xn--)
#
# +noidnout: The string is sent as-is to the server and the returned qname is
#            displayed in the same form.
# +idnout:   The string is sent as-is to the server and the returned qname is
#            displayed as the corresponding U-label.
#
# The "+[no]idnin" flag has no effect in these cases.

text="Checking valid A-label"
idna_test "$text" ""                   "xn--nxasmq6b.com" "βόλοσ.com." 
idna_test "$text" "+noidnin +noidnout" "xn--nxasmq6b.com" "xn--nxasmq6b.com."
idna_test "$text" "+noidnin +idnout"   "xn--nxasmq6b.com" "βόλοσ.com." 
idna_test "$text" "+idnin +noidnout"   "xn--nxasmq6b.com" "xn--nxasmq6b.com."
idna_test "$text" "+idnin +idnout"     "xn--nxasmq6b.com" "βόλοσ.com." A



# Tests of a fake A-label
#
# +noidnin: The label is sent as-is to the server and dig will display the
#           returned fake A-label in the same form.
# +idnin:   "dig" should report that the label is not correct.
#
# The +[no]idnout options should not have any effect on the test.

text="Checking invalid A-label"
idna_fail "$text" ""                   "xn--ahahah"
idna_test "$text" "+noidnin +noidnout" "xn--ahahah" "xn--ahahah."
idna_test "$text" "+noidnin +idnout"   "xn--ahahah" "xn--ahahah."
idna_fail "$text" "+idnin   +noidnout" "xn--ahahah"
idna_fail "$text" "+idnin   +idnout"   "xn--ahahah"



# Tests of a valid unicode string but an invalid U-label
#
# Symbols are not valid IDNA names.
#
# +noidnin: "dig" should send unicode octets to the server and display the
#           returned qname in the same form.
# +idnin:   "dig" should generate an error.
#
# The +[no]idnout options should not have any effect on the test.

text="Checking invalid U-label"
idna_fail "$text" ""                   "❤︎.com"
idna_test "$text" "+noidnin +noidnout" "❤︎.com" "\226\157\164\239\184\142.com."
idna_test "$text" "+noidnin +idnout"   "❤︎.com" "\226\157\164\239\184\142.com."
idna_fail "$text" "+idnin   +noidnout" "❤︎.com"
idna_fail "$text" "+idnin   +idnout"   "❤︎.com"

exit $status
