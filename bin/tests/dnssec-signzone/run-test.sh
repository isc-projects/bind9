#!/bin/sh


sign="../../dnssec/dnssec-signzone -f signed.zone -o example.com."

signit() {
	rm -f signed.zone
	grep '^;' $zone
	$sign $zone
}

expect_success() {
	if ! test -f signed.zone ; then
		echo "Error: expected success, but sign failed for $zone."
	else
		echo "Success:  Sign succeeded for $zone."
	fi
}

expect_failure() {
	if test -f signed.zone ; then
		echo "Error: expected failure, but sign succeeded for $zone."
	else
		echo "Success:  Sign failed (expected) for $zone"
	fi
}

zone="test1.zone" ; signit ; expect_success
zone="test2.zone" ; signit ; expect_failure
zone="test3.zone" ; signit ; expect_failure
zone="test4.zone" ; signit ; expect_success
zone="test5.zone" ; signit ; expect_failure
zone="test6.zone" ; signit ; expect_failure
zone="test7.zone" ; signit ; expect_failure
zone="test8.zone" ; signit ; expect_failure
