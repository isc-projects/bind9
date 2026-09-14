# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# pylint: disable=invalid-name

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import total_ordering
from pathlib import Path

import glob
import os
import re


from isctest.algorithms import ALL_ALGORITHMS_BY_NUM, ECDSAP256SHA256, Algorithm
from isctest.run import EnvCmd
from isctest.zone import FileZoneKey

import isctest.log
import isctest.query
import isctest.util

DEFAULT_TTL = 300


def Ipub(config):
    return (
        config["dnskey-ttl"]
        + config["zone-propagation-delay"]
        + config["publish-safety"]
    )


def IpubC(config, rollover=True):
    ttl1 = config["dnskey-ttl"] + config["publish-safety"]
    ttl2 = timedelta(0)

    if not rollover:
        # If this is the first key, we also need to wait until the zone
        # signatures are omnipresent. Use max-zone-ttl instead of
        # dnskey-ttl, and no publish-safety (because we are looking at
        # signatures here, not the public key).
        ttl2 = config["max-zone-ttl"]

    return config["zone-propagation-delay"] + max(ttl1, ttl2)


def Iret(config, zsk=True, ksk=False, rollover=True, smooth=True):
    sign_delay = timedelta(0)
    safety_interval = timedelta(0)
    if rollover:
        if smooth:
            sign_delay = config["signatures-validity"] - config["signatures-refresh"]
        safety_interval = config["retire-safety"]

    iret_ksk = timedelta(0)
    if ksk:
        # KSK: Double-KSK Method: Iret = DprpP + TTLds
        iret_ksk = (
            config["parent-propagation-delay"] + config["ds-ttl"] + safety_interval
        )

    iret_zsk = timedelta(0)
    if zsk:
        # ZSK: Pre-Publication Method: Iret = Dsgn + Dprp + TTLsig
        iret_zsk = (
            sign_delay
            + config["zone-propagation-delay"]
            + config["max-zone-ttl"]
            + safety_interval
        )

    return max(iret_ksk, iret_zsk)


@total_ordering
class KeyTimingMetadata:
    """
    Represent a single timing information for a key.

    These objects can be easily compared, support addition and subtraction of
    timedelta objects or integers(value in seconds). A lack of timing metadata
    in the key (value 0) should be represented with None rather than an
    instance of this object.
    """

    FORMAT = "%Y%m%d%H%M%S"

    def __init__(self, timestamp: str):
        if int(timestamp) <= 0:
            raise ValueError(f'invalid timing metadata value: "{timestamp}"')
        self.value = datetime.strptime(timestamp, self.FORMAT).replace(
            tzinfo=timezone.utc
        )

    def __repr__(self):
        return self.value.strftime(self.FORMAT)

    def __str__(self) -> str:
        return self.value.strftime(self.FORMAT)

    def __add__(self, other: timedelta | int):
        if isinstance(other, int):
            other = timedelta(seconds=other)
        result = KeyTimingMetadata.__new__(KeyTimingMetadata)
        result.value = self.value + other
        return result

    def __sub__(self, other: timedelta | int):
        if isinstance(other, int):
            other = timedelta(seconds=other)
        result = KeyTimingMetadata.__new__(KeyTimingMetadata)
        result.value = self.value - other
        return result

    def __iadd__(self, other: timedelta | int):
        if isinstance(other, int):
            other = timedelta(seconds=other)
        self.value += other

    def __isub__(self, other: timedelta | int):
        if isinstance(other, int):
            other = timedelta(seconds=other)
        self.value -= other

    def __lt__(self, other: "KeyTimingMetadata"):
        return self.value < other.value

    def __eq__(self, other: object):
        return isinstance(other, KeyTimingMetadata) and self.value == other.value

    @staticmethod
    def now() -> "KeyTimingMetadata":
        result = KeyTimingMetadata.__new__(KeyTimingMetadata)
        result.value = datetime.now(timezone.utc)
        return result


class KeyProperties:
    """
    Represent the (expected) properties a key should have.
    """

    def __init__(
        self,
        name: str,
        metadata: dict,
        timing: dict[str, KeyTimingMetadata],
        private: bool = True,
        legacy: bool = False,
        role: str = "csk",
        ttl: int = 3600,
        flags: int = 257,
        keytag_min: int = 0,
        keytag_max: int = 65535,
        offset: timedelta | int = 0,
    ):
        self.name = name
        self.key = None
        self.metadata = metadata
        self.timing = timing
        # Properties
        self.private = private
        self.legacy = legacy
        self.role = role
        self.ttl = ttl
        self.flags = flags
        self.keytag_min = keytag_min
        self.keytag_max = keytag_max
        self.offset = offset

    def __repr__(self):
        return self.name

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def default(with_state=True) -> "KeyProperties":
        metadata = {
            "Algorithm": ECDSAP256SHA256.number,
            "Length": 256,
            "Lifetime": 0,
            "KSK": "yes",
            "ZSK": "yes",
        }
        timing: dict[str, KeyTimingMetadata] = {}

        result = KeyProperties(name="DEFAULT", metadata=metadata, timing=timing)
        result.name = "DEFAULT"
        result.key = None
        if with_state:
            result.metadata["GoalState"] = "omnipresent"
            result.metadata["DNSKEYState"] = "rumoured"
            result.metadata["KRRSIGState"] = "rumoured"
            result.metadata["ZRRSIGState"] = "rumoured"
            result.metadata["DSState"] = "hidden"

        return result

    def role_full(self) -> str:
        if self.flags == 256:
            return "zone-signing"
        return "key-signing"

    def Ipub(self, config):
        ipub = timedelta(0)

        if self.key.get_metadata("Predecessor", must_exist=False) != "undefined":
            ipub = Ipub(config)

        self.timing["Active"] = self.timing["Published"] + ipub

    def IpubC(self, config):
        if not self.key.is_ksk():
            return

        rollover = self.key.get_metadata("Predecessor", must_exist=False) != "undefined"
        ipubc = IpubC(config, rollover)

        self.timing["PublishCDS"] = self.timing["Published"] + ipubc

        if "Lifetime" in self.metadata and self.metadata["Lifetime"] != 0:
            self.timing["DeleteCDS"] = (
                self.timing["PublishCDS"] + self.metadata["Lifetime"]
            )

    def Iret(self, config):
        if "Lifetime" not in self.metadata or self.metadata["Lifetime"] == 0:
            return

        sigdel = self.key.get_timing("SigRemoved", must_exist=False)
        smooth = sigdel is None
        iret = Iret(config, zsk=self.key.is_zsk(), ksk=self.key.is_ksk(), smooth=smooth)
        self.timing["Removed"] = self.timing["Retired"] + iret

    def set_expected_keytimes(
        self, config, offset=None, pregenerated=False, migrate=False
    ):
        if self.key is None:
            raise ValueError("KeyProperties must be attached to a Key")

        if self.legacy:
            return

        if offset is None:
            offset = self.offset

        self.timing["Generated"] = self.key.get_timing("Created")
        self.timing["Published"] = self.key.get_timing("Created")
        if pregenerated:
            self.timing["Published"] = self.key.get_timing("Publish")

        if migrate:
            self.timing["Published"] = self.key.get_timing("Publish")
            if self.key.is_ksk():
                self.timing["PublishCDS"] = self.key.get_timing("SyncPublish")
            self.timing["Active"] = self.key.get_timing("Activate")
        else:
            self.timing["Published"] = self.timing["Published"] + offset
            self.Ipub(config)
            self.IpubC(config)

        # Set Retired timing metadata if key has lifetime.
        if "Lifetime" in self.metadata and self.metadata["Lifetime"] != 0:
            self.timing["Retired"] = self.timing["Active"] + self.metadata["Lifetime"]

        self.Iret(config)

        # Key state change times must exist, but since we cannot reliably tell
        # when named made the actual state change, we don't care what the
        # value is. Set it to None will verify that the metadata exists, but
        # without actual checking the value.
        self.timing["DNSKEYChange"] = None

        if self.key.is_ksk():
            self.timing["DSChange"] = None
            self.timing["KRRSIGChange"] = None

        if self.key.is_zsk():
            self.timing["ZRRSIGChange"] = None


# pylint: disable=invalid-name
@dataclass
class SettimeOptions:

    P: str | None = None
    """-P date/[+-]offset/none: set/unset key publication date"""

    P_ds: str | None = None
    """-P ds date/[+-]offset/none: set/unset DS publication date"""

    P_sync: str | None = None
    """-P sync date/[+-]offset/none: set/unset CDS and CDNSKEY publication date"""

    A: str | None = None
    """-A date/[+-]offset/none: set/unset key activation date"""

    R: str | None = None
    """-R date/[+-]offset/none: set/unset key revocation date"""

    I: str | None = None
    """-I date/[+-]offset/none: set/unset key inactivation date"""

    D: str | None = None
    """-D date/[+-]offset/none: set/unset key deletion date"""

    D_ds: str | None = None
    """-D ds date/[+-]offset/none: set/unset DS deletion date"""

    D_sync: str | None = None
    """-D sync date/[+-]offset/none: set/unset CDS and CDNSKEY deletion date"""

    g: str | None = None
    """-g state: set the goal state for this key"""

    d: str | None = None
    """-d state date/[+-]offset: set the DS state"""

    k: str | None = None
    """-k state date/[+-]offset: set the DNSKEY state"""

    r: str | None = None
    """-r state date/[+-]offset: set the RRSIG (KSK) state"""

    z: str | None = None
    """-z state date/[+-]offset: set the RRSIG (ZSK) state"""

    def __str__(self):
        args = []
        for opt, value in self.__dict__.items():
            if value is None:
                continue
            if not isinstance(value, str):
                raise ValueError(f"{opt}: invalid option value, only string supported")
            opt_str = opt.replace("_", " ")
            args.append(f"-{opt_str} {value}")
        return " ".join(args)


@total_ordering
class Key(FileZoneKey):
    """
    A FileZoneKey specialized with KASP timing and state-file operations.

    Inherits the key-material accessors (dnskey, into_ta, ...) from FileZoneKey
    and adds the metadata reads, signing-state derivation, and timing
    convenience operations used by the KASP/rollover tests.
    """

    def __init__(self, name: str, keydir: str | Path | None = None):
        super().__init__(name, keydir)
        self.statefile = f"{self.path}.state"
        self.external = False

    def get_timing(
        self, metadata: str, must_exist: bool = True
    ) -> KeyTimingMetadata | None:
        regex = rf";\s+{metadata}:\s+(\d+).*"
        with open(self.keyfile, "r", encoding="utf-8") as file:
            for line in file:
                match = re.match(regex, line)
                if match is not None:
                    try:
                        return KeyTimingMetadata(match.group(1))
                    except ValueError:
                        break
        if must_exist:
            raise ValueError(
                f'timing metadata "{metadata}" for key "{self.name}" invalid'
            )
        return None

    def get_metadata(
        self, metadata: str, file=None, comment=False, must_exist=True
    ) -> str:
        if file is None:
            file = self.statefile
        value = "undefined"
        regex = rf"{metadata}:\s+(\S+).*"
        if comment:
            # The expected metadata is prefixed with a ';'.
            regex = rf";\s+{metadata}:\s+(\S+).*"
        with open(file, "r", encoding="utf-8") as fp:
            for line in fp:
                match = re.match(regex, line)
                if match is not None:
                    value = match.group(1)
                    break
        if must_exist and value == "undefined":
            raise ValueError(
                f'metadata "{metadata}" for key "{self.name}" in file "{file}" undefined'
            )
        return value

    def get_signing_state(
        self, offline_ksk=False, zsk_missing=False, smooth=False
    ) -> tuple[bool, bool]:
        """
        This returns the signing state derived from the key states, KRRSIGState
        and ZRRSIGState.

        If 'offline_ksk' is set to True, we determine the signing state from
        the timing metadata. If 'zsigning' is True, ensure the current time is
        between the Active and Retired timing metadata.

        If 'zsk_missing' is set to True, it means the ZSK private key file is
        missing, and the KSK should take over signing the RRset, and the
        expected zone signing state (zsigning) is reversed.

        If 'smooth' is set to True, it means a smooth ZSK rollover is
        initiated. Signatures are being replaced gradually during a ZSK
        rollover, so the existing signatures of the predecessor ZSK are still
        being used, thus the predecessor is expected to be signing.
        """
        # Fetch key timing metadata.
        now = KeyTimingMetadata.now()
        activate = self.get_timing("Activate")
        assert activate is not None  # to silence mypy - its implied by line above
        inactive = self.get_timing("Inactive", must_exist=False)

        active = now >= activate
        retired = inactive is not None and inactive <= now
        signing = active and not retired

        # Fetch key state metadata.
        krrsigstate = self.get_metadata("KRRSIGState", must_exist=False)
        ksigning = krrsigstate in ["rumoured", "omnipresent"]
        zrrsigstate = self.get_metadata("ZRRSIGState", must_exist=False)
        zsigning = zrrsigstate in ["rumoured", "omnipresent"]
        if smooth:
            zsigning = zrrsigstate in ["unretentive", "omnipresent"]

        if ksigning:
            assert self.is_ksk()
        if zsigning:
            assert self.is_zsk()

        # If the ZSK private key file is missing, revers the zone signing state.
        if zsk_missing:
            zsigning = not zsigning

        # If testing offline KSK, retrieve the signing state from the key timing
        # metadata.
        if offline_ksk and signing and self.is_zsk():
            assert zsigning
        if offline_ksk and signing and self.is_ksk():
            ksigning = signing

        return ksigning, zsigning

    def is_ksk(self) -> bool:
        # KASP role follows the .state KSK metadata, not the DNSKEY SEP flag:
        # a CSK may be configured without SEP (see the csk-nosep test).
        return self.get_metadata("KSK") == "yes"

    def is_zsk(self) -> bool:
        return self.get_metadata("ZSK") == "yes"

    def role(self) -> str:
        if self.is_ksk() and self.is_zsk():
            return "CSK"
        if self.is_ksk():
            return "KSK"
        return "ZSK"

    @property
    def algorithm(self) -> Algorithm:
        num = int(self.get_metadata("Algorithm"))
        return ALL_ALGORITHMS_BY_NUM[num]

    def dnskey_equals(self, value, cdnskey=False):
        dnskey = value.split()

        if cdnskey:
            # fourth element is the rrtype
            assert dnskey[3] == "CDNSKEY"
            dnskey[3] = "DNSKEY"

        dnskey_fromfile = []
        rdata = " ".join(dnskey[:7])

        with open(self.keyfile, "r", encoding="utf-8") as file:
            for line in file:
                if f"{rdata}" in line:
                    dnskey_fromfile = line.split()

        pubkey_fromfile = "".join(dnskey_fromfile[7:])
        pubkey_fromwire = "".join(dnskey[7:])

        return pubkey_fromfile == pubkey_fromwire

    def cds_equals(self, value, alg):
        cds = value.split()

        dsfromkey_command = [
            os.environ.get("DSFROMKEY"),
            "-T",
            str(self.dnskey.ttl),
            "-a",
            alg,
            "-C",
            "-w",
            str(self.keyfile),
        ]

        cmd = isctest.run.cmd(dsfromkey_command)
        dsfromkey = cmd.out.split()

        rdata_fromfile = " ".join(dsfromkey[:7])
        rdata_fromwire = " ".join(cds[:7])
        if rdata_fromfile != rdata_fromwire:
            isctest.log.debug(
                f"CDS RDATA MISMATCH: {rdata_fromfile} - {rdata_fromwire}"
            )
            return False

        digest_fromfile = "".join(dsfromkey[7:]).lower()
        digest_fromwire = "".join(cds[7:]).lower()
        if digest_fromfile != digest_fromwire:
            isctest.log.debug(
                f"CDS DIGEST MISMATCH: {digest_fromfile} - {digest_fromwire}"
            )
            return False

        return digest_fromfile == digest_fromwire

    def is_metadata_consistent(self, key, metadata, checkval=True):
        """
        If 'key' exists in 'metadata' then it must also exist in the state
        meta data. Otherwise, it must not exist in the state meta data.
        If 'checkval' is True, the meta data values must also match.
        """
        if key in metadata:
            if checkval:
                value = self.get_metadata(key)
                if value != f"{metadata[key]}":
                    isctest.log.debug(
                        f"{self.name} {key} METADATA MISMATCH: {value} - {metadata[key]}"
                    )
                return value == f"{metadata[key]}"

            return self.get_metadata(key) != "undefined"

        value = self.get_metadata(key, must_exist=False)
        if value != "undefined":
            isctest.log.debug(f"{self.name} {key} METADATA UNEXPECTED: {value}")
        return value == "undefined"

    def is_timing_consistent(self, key, timing, file, comment=False):
        """
        If 'key' exists in 'timing' then it must match the value in the state
        timing data. Otherwise, it must also not exist in the state timing data.
        """
        if key in timing:
            value = self.get_metadata(key, file=file, comment=comment)
            if value != str(timing[key]):
                isctest.log.debug(
                    f"{self.name} {key} TIMING MISMATCH: {value} - {timing[key]}"
                )
            return value == str(timing[key])

        value = self.get_metadata(key, file=file, comment=comment, must_exist=False)
        if value != "undefined":
            isctest.log.debug(f"{self.name} {key} TIMING UNEXPECTED: {value}")
        return value == "undefined"

    def _check_public_key_file(self, zone, properties):
        """
        Check the public key file.
        """
        role = properties.role_full()
        comment = f"This is a {role} key, keyid {self.tag}, for {zone}."
        if not isctest.util.file_contents_contain(self.keyfile, comment):
            isctest.log.debug(f"{self.name} COMMENT MISMATCH: expected '{comment}'")
            return False

        ttl = properties.ttl
        flags = properties.flags
        alg = properties.metadata["Algorithm"]
        dnskey = f"{zone}. {ttl} IN DNSKEY {flags} 3 {alg}"
        if not isctest.util.file_contents_contain(self.keyfile, dnskey):
            isctest.log.debug(f"{self.name} DNSKEY MISMATCH: expected '{dnskey}'")
            return False

        return True

    def _check_private_key_file(self, properties):
        """
        Check the private key file.
        """
        if not properties.private:
            return True

        alg = properties.metadata["Algorithm"]

        # Retrieve creation date.
        created = self.get_metadata("Generated")

        pval = self.get_metadata("Created", file=self.privatefile)
        if pval != created:
            isctest.log.debug(
                f"{self.name} Created METADATA MISMATCH: {pval} - {created}"
            )
            return False
        pval = self.get_metadata("Private-key-format", file=self.privatefile)
        if pval != "v1.3":
            isctest.log.debug(
                f"{self.name} Private-key-format METADATA MISMATCH: {pval} - v1.3"
            )
            return False
        pval = self.get_metadata("Algorithm", file=self.privatefile)
        if pval != f"{alg}":
            isctest.log.debug(
                f"{self.name} Algorithm METADATA MISMATCH: {pval} - {alg}"
            )
            return False

        return True

    def _check_key_state_file(self, zone, properties):
        """
        Check the key state file.
        """
        if properties.legacy:
            return True

        comment = f"This is the state of key {self.tag}, for {zone}."
        if not isctest.util.file_contents_contain(self.statefile, comment):
            isctest.log.debug(f"{self.name} COMMENT MISMATCH: expected '{comment}'")
            return False

        attributes = [
            "Lifetime",
            "Algorithm",
            "Length",
            "KSK",
            "ZSK",
            "GoalState",
            "DNSKEYState",
            "KRRSIGState",
            "ZRRSIGState",
            "DSState",
        ]
        for key in attributes:
            if not self.is_metadata_consistent(key, properties.metadata):
                return False

        # Check tag range.
        if self.tag < properties.keytag_min:
            return False
        if self.tag > properties.keytag_max:
            return False

        return True

    def match_properties(self, zone, properties):
        """
        Check the key with given properties.
        """
        # Check file existence.
        # Noop. If file is missing then the get_metadata calls will fail.

        if not self._check_public_key_file(zone, properties):
            return False

        if not self._check_private_key_file(properties):
            return False

        if not self._check_key_state_file(zone, properties):
            return False

        return True

    def match_timingmetadata(self, timings, file=None, comment=False):
        if file is None:
            file = self.statefile

        attributes = [
            "Generated",
            "Created",
            "Published",
            "Publish",
            "PublishCDS",
            "SyncPublish",
            "Active",
            "Activate",
            "Retired",
            "Inactive",
            "Revoked",
            "Removed",
            "Delete",
        ]
        for key in attributes:
            if not self.is_timing_consistent(key, timings, file, comment=comment):
                isctest.log.debug(f"{self.name} TIMING METADATA MISMATCH: {key}")
                return False

        return True

    def settime(self, options: SettimeOptions, with_state=True):
        if with_state:
            settime_cmd = EnvCmd("SETTIME", "-s")
        else:
            settime_cmd = EnvCmd("SETTIME")

        settime_cmd(f"{options} {self.path}")

    def __lt__(self, other: "Key"):
        return self.name < other.name

    def __eq__(self, other: object):
        return isinstance(other, Key) and self.path == other.path

    def __repr__(self):
        return self.path


def keydir_to_keylist(
    zone: str | None, keydir: str | None = None, in_use: bool = False
) -> list[Key]:
    """
    Retrieve all keys from the key files in a directory. If 'zone' is None,
    retrieve all keys in the directory, otherwise only those matching the
    zone name. If 'keydir' is None, search the current directory.
    """
    if zone is None:
        zone = ""

    all_keys = []
    if keydir is None:
        regex = rf"(K{zone}\.\+.*\+.*)\.key"
        for filename in glob.glob(f"K{zone}.+*+*.key"):
            match = re.match(regex, filename)
            if match is not None:
                all_keys.append(Key(match.group(1)))
    else:
        regex = rf"{keydir}/(K{zone}\.\+.*\+.*)\.key"
        for filename in glob.glob(f"{keydir}/K{zone}.+*+*.key"):
            match = re.match(regex, filename)
            if match is not None:
                all_keys.append(Key(match.group(1), keydir))

    states = ["GoalState", "DNSKEYState", "KRRSIGState", "ZRRSIGState", "DSState"]

    def used(kk):
        if not in_use:
            return True

        for state in states:
            val = kk.get_metadata(state, must_exist=False)
            if val not in ["undefined", "hidden"]:
                isctest.log.debug(f"key {kk} in use")
                return True

        return False

    return [k for k in all_keys if used(k)]


def keystr_to_keylist(keystr: str, keydir: str | None = None) -> list[Key]:
    return [Key(name, keydir) for name in keystr.split()]


def policy_to_properties(ttl, keys: list[str]) -> list[KeyProperties]:
    """
    Get the policies from a list of specially formatted strings.
    The splitted line should result in the following items:
    line[0]: Role
    line[1]: Lifetime
    line[2]: Algorithm
    line[3]: Length
    Then, optional data for specific tests may follow:
    - "goal", "dnskey", "krrsig", "zrrsig", "ds", followed by a value,
      sets the given state to the specific value
    - "missing", set if the private key file for this key is not available.
    - "offset", an offset for testing key rollover timings
    - "tag-range", followed by <min>-<max> to test key tag ranges
    """
    proplist = []
    count = 0
    for key in keys:
        count += 1
        line = key.split()

        # defaults
        metadata: dict[str, str | int] = {}
        timing: dict[str, KeyTimingMetadata] = {}
        private = True
        legacy = False
        keytag_min = 0
        keytag_max = 65535
        offset = timedelta(0)

        role = line[0]
        if role == "zsk":
            flags = 256
            metadata["ZSK"] = "yes"
            metadata["KSK"] = "no"
        else:
            flags = 257
            metadata["ZSK"] = "yes" if role == "csk" else "no"
            metadata["KSK"] = "yes"

        metadata["Algorithm"] = line[2]
        metadata["Length"] = line[3]
        if line[1] == "unlimited":
            metadata["Lifetime"] = 0
        elif line[1] != "-":
            metadata["Lifetime"] = int(line[1])

        for i in range(4, len(line)):
            if line[i].startswith("goal:"):
                keyval = line[i].split(":")
                metadata["GoalState"] = keyval[1]
            elif line[i].startswith("dnskey:"):
                keyval = line[i].split(":")
                metadata["DNSKEYState"] = keyval[1]
            elif line[i].startswith("krrsig:"):
                keyval = line[i].split(":")
                metadata["KRRSIGState"] = keyval[1]
            elif line[i].startswith("zrrsig:"):
                keyval = line[i].split(":")
                metadata["ZRRSIGState"] = keyval[1]
            elif line[i].startswith("ds:"):
                keyval = line[i].split(":")
                metadata["DSState"] = keyval[1]
            elif line[i].startswith("offset:"):
                keyval = line[i].split(":")
                offset = timedelta(seconds=int(keyval[1]))
            elif line[i].startswith("tag-range:"):
                keyval = line[i].split(":")
                tagrange = keyval[1].split("-")
                keytag_min = int(tagrange[0])
                keytag_max = int(tagrange[1])
            elif line[i] == "missing":
                private = False
            else:
                assert False, f"undefined optional data {line[i]}"

        keyprop = KeyProperties(
            name=f"KEY{count}",
            metadata=metadata,
            timing=timing,
            private=private,
            legacy=legacy,
            role=role,
            ttl=ttl,
            flags=flags,
            keytag_min=keytag_min,
            keytag_max=keytag_max,
            offset=offset,
        )
        proplist.append(keyprop)

    return proplist


def private_type_record(zone: str, key: Key, rrtype: int = 65534) -> str:
    """
    Write a private type record recording the state of the signing process for
    a given zone and key, print the private type record with given RRtype,
    indicating that the signing process for this key is completed.
    """
    keyid = key.tag
    wire_alg = key.algorithm.number
    return f"{zone}. 0 IN TYPE{rrtype} \\# 5 {wire_alg:02x}{keyid:04x}0000"
