; Copyright (C) 2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
;
; This Source Code Form is subject to the terms of the Mozilla Public
; License, v. 2.0. If a copy of the MPL was not distributed with this
; file, You can obtain one at http://mozilla.org/MPL/2.0/.

; $Id: bindevt.mc,v 1.4 2007/06/19 23:47:24 tbox Exp $

MessageIdTypedef=DWORD

LanguageNames = (English=0x409:MSG00409)

OutputBase = 16


MessageId=0x1
Severity=Error
Facility=Application
SymbolicName=BIND_ERR_MSG
Language=English
%1
.

MessageId=0x2
Severity=Warning
Facility=Application
SymbolicName=BIND_WARN_MSG
Language=English
%1
.

MessageId=0x3
Severity=Informational
Facility=Application
SymbolicName=BIND_INFO_MSG
Language=English
%1
.
