
    mDN Wrapper - Client Side mDN Conversion for Windows

    Copyright (c) 2000,2001 Japan Network Information Center.
                All rights reserved.

    *** IMPORTANT NOTICE ********************************************
    If you install a new version of mDN Wrapper to a machine where
    older version is already installed, you need to rewrap all the
    programs that has been wrapped when you first use the new version.
    This can be done by pressing "Rewrap All" button from the
    configuration GUI.
    *****************************************************************


1. Introduction

    For supporting multi-lingual domain name on Windows, client 
    application should convert domain names (their encodings) to that
    DNS server accepts.  Ofcourse, this requires windows applications to
    handle multi-lingualized domain names in its core, and it is maker's
    responsibility to make program mDN compatible.

    But now, there are still no acceptable standard for mDN, it is
    difficult to expect software providers to create mDN version of the 
    programs.  So, some tricks to make legacy application to do client 
    side mDN conversions.  'mdnsproxy' in mDNkit is one of such solution,
    and also this one, WINSOCK Wrapper is another solution.

    On windows, name resolving request is passed to WINSOCK DLL. So,
    replacing WINSOCK DLL with multi-lingual domain name version makes
    legacy windows applications compatible with mDN.

2. Architecture

2.1. Wrapper DLL

    Wrapper DLL resides between application and original DLL.  It
    intercept application's calls to original DLL, and preforms some
    additional processing on those calls.

    +------------+  Call  +------------+  Call  +------------+
    |            |------->|            |------->|            |
    |Application |        |Wrapper DLL |        |Original DLL|
    |            |<-------|            |<-------|            |
    +------------+ Return +------------+ Return +------------+
                           additional
			   processing
			   here

    DLL call from apllication is passed to wrapper DLL.  Wrapper DLL
    then performs some additional processing on that call, and then
    calls original DLL.  Also, result from original DLL will once passed
    to wrapper DLL and wrapper does additional process on that result,
    and finally result will passed to the application.

    mDN wrapper provides wrapper DLLs for WINSOCK,
    
        WSOCK32.DLL     WINSOCK V1.1
	WS2_32.DLL      WINSOCK V2.0

    to resolve multi-lingual domain names.

2.2. Wrapping APIs

    mDN Wrapper performs additional processing on name resolving APIs in
    WINSOCK, listed below.

    both WINSOCK 1.1, WINSOCK 2.0
    
        gethostbyaddr
	gethostbyname
	WSAAsyncGetHostByAddr
	WSAAsyncGetHostByName
	
    only in WINSOCK 2.0
    
        WSALookupServiceBeginA
	WSALookupServiceNextA
	WSALookupServiceEnd

    Some applications do not use these APIs to resolve domaimn names. 
    'nslookup' is one of those program. 'nslookup' builds and parse DNS
    messages internally and does not use WINSOCK's name resolve APIs.
    mDN Wrapper cannot multi-ligualize those programs.
    
    NOTE:   You can use 'mdnsproxy' to multi-ligualize those program.
            'mdnsproxy' intercepts DNS reqesut/response on the network
            and convert encoding of domain names. 

    NOTE:   WINSOCK 2.0 also contains WIDE-CHARACTER based name
            resolution APIs,

                WSALookupServiceBeginW
                WSALookupServiceNextW

            mDN Wrapper does not wrap these APIs.  These APIs are used
            on microsoft's internartionalization, and used on their I18N
            framework.  It should be dangerouse to convert to another
            multi-ligualization frame work.
    
2.3. Other APIs in WINSOCK

    For another APIs in WINSOCK, mDN wrapper does nothing, only calls
    original DLL's entries.

    mDN wrapper copies original WINSOCK DLLs with renaming
    as below, and forward requests to them.

        wsock32.dll     ->  wsock32o.dll
	ws2_32.dll      ->  ws2_32o.dll

    Wrappper DLL will installed with original DLL names. So after
    install of mDN wrapper, WINSOCK DLLs should be

        wsock32.dll         mDN Wrapper for WINSOCK V1.1
	ws2_32.dll          mDN Wrapper for WINSOCK V2.0
	wsock32o.dll        Original WINSOCK V1.1 DLL
	ws2_32o.dll         Original WINSOCK V2.0 DLL 

2.4. Asynchronous API

    Domain name conversion take place on
    
        request to DNS

            convert from local encoding to DNS compatible encoding

        response from DNS

            convert from DNS encoding to local encoding

    For synchronous APIs, local to DNS conversion is done before calling
    original API, and after return from original API, name should be
    converted from DNS encoding to local encoding.

    But WINSOCK having some asynchronous APIs, such as

	WSAAsyncGetHostByAddr
	WSAAsyncGetHostByName

    In these APIs, completion is notified with windows message.  To
    perform DNS to local conversion, wrapper should hook target window
    procedure to capture those completion messages.
    
    So, if asynchronous API was called, mDN wrapper set hook to target
    window procedure (passed with API parameter).  If hook found
    notify message (also given with API parameter), then convert
    resulting name (in DNS encoding) to local encoding.
    
2.5. Installing Wrapper DLLs

    WINSOCK DLLs are placed at windows's system directory.  To wrap
    WINSOCK DLLs, one should do following sequence at system directory.

        Rename Original WINSOCK DLLs

	    ren wsock32.dll wsock32o.dll
	    ren ws2_32.dll  ws2_32o.dll

        Install (copy in) Wrapper DLLs

	    copy somewhere\wsock32.dll wsock32.dll
	    copy somewhere\ws2_32.dll  ws2_32.dll
	    copy another DLLs also

    But, replacing DLLs in window's system directory is very dangerous.

    a)  If you want to re-install wrappers again, original WINSOCK DLLs
        may be lost.

    b)  Some application or service pack will replace WINSOCK DLLs.  It
        may corrupt WINSOCK environment.

    If these happen, at least networking does not work, and worse,
    Windows never startup again.

    So, mDN wrapper usually does not wrap on system, but wrap on
    indivisual applications.

    In Windows, DLL will be searched in the following places:
    
        Application's Load Directory
	%SystemRoot%\System32
	%SystemRoot%
	Directories in PATH

    and load & linked first found one.  So if installed wrapper DLLs on
    application's load directory, application's call to WINSOCK will
    wrapped.

    But some applications or DLLs are binded to specific DLL, they does
    not rely on above DLL's search path.  For those applcaitons or DLLs,
    mDN wrapper (in standard installation) cannot wrap them.

    NOTE:   Netscape is one of those program.  It cannot be wrapped if
            installed to applications directory.  Also WINSOCK DLLs are
            also binded to related DLLs in system directory.  On the
            other hand, Internet Explore or Window Media Player relys on
            standard DLL search path, and well wrapped with mDN wrapper.

2.6. At which point conversion applied

    If windows supporting WINSOCK 2.0, there are DLLs one for 1.1 and
    another for 2.0, and call to WINSOCK 1.1 will redirected to 2.0 DLL.

        +------------+  Call  +------------+  Call  +------------+
        |            |------->|            |------->|            |
        |Application |        |WINSOCK 1.1 |        |WINSOCK 2.0 |
        |            |<-------|            |<-------|            |
        +------------+ Return +------------+ Return +------------+

    In this case, calls to 1.1 and 2.0 are both passed to 2.0 DLL.  So
    conversion will done in WINSOCK 2.0 DLL side.

    If windows only supports WINSOCK 1.1, there's 1.1 DLL only.

        +------------+  Call  +------------+
        |            |------->|            |
        |Application |        |WINSOCK 1.1 |
        |            |<-------|            |
        +------------+ Return +------------+

    In this case, conversion must done in 1.1 DLL.

    If mDN Wrapper was installed on system directory, DLLs will work as
    described above.  But if wrapper was installed on application's
    directory, call/return sequence changes.  Original WINSOCK 1.1 DLL
    in windows seems binded to specific WINSOCK 2.0 DLL, placed at
    window's system diretory.  So call from WINSOCK 1.1 to WINSOCK 2.0
    will passed to original DLL (in system directory) and never passed
    to wrapper DLL in application's directory.  So in this case, both
    1.1 and 2.0 DLLs should coonvert domain name encodings.
    
    These DLL binding is not documented.  It may be change on OS
    versions or DLL versions.  So, mDn wrapper determines place of
    conversion on registry value.  With this registry value, mDN
    wrappper absolb OS/DLL variations.
    
    Registry values for mDN Wrapper will placed under

        HKEY_LOCAL_MACHINE\SOFTWARE\JPNIC\MDN
	HKEY_CURRENT_USER\SOFTWARE\JPNIC\MDN

    Place of conversion is determined with registry value "Where",
    
        Registry Value "Where"   REG_DWORD
	    
	    0       both on WINSOCK 1.1 and WINSOCK 2.0
	    1       if WINSOCK 2.0 exist, only in WINSOCK 2.0
	            otherwise, convert on WINSOCK 1.1
            2       only in WINSOCK 1.1
	    3       only in WINSOCK 2.0

    If you install mDN wrapper into application's directory, use "0".
    If you install mDN wrapper into system directory, use "1".  If there
    are no "Where" value, mDN wrapper uses "0" as default, it is suited
    to installation into application's directory (default installation).

2.7. Converting From/To

    Wrapper DLL convert resolving domain name encoded with local code to
    DNS server's encoding.  Also, wrapper DLL convert resulting name (
    encoded with DNS's encoding) back to local encoding.
    
    There are several proposals for DNS encodings to handle multi-lingual
    domain names.  Wrapper DLL should be configured to convert to one of
    those encodings.  This DNS side encoding will specified with
    registry.  When installing mDN wrapper, this registry will set to
    some (yet undefined) DNS encoding.
    
    Registry values for mDN Wrapper will placed under

        HKEY_LOCAL_MACHINE\SOFTWARE\JPNIC\MDN
	HKEY_CURRENT_USER\SOFTWARE\JPNIC\MDN

    DNS encoding name will given with registry value (REG_SZ) of "Encoding",
    this name must be one of encoding names which 'libmdn' recognize.

        Registry Value "Encoding"   REG_SZ
	
	    Encoding name of DNS server accepts.
    
    Local encodings (Windows Apllication Encodings) is generally
    acquired from process's code page.  'iconv' library, used for mDN
    wrapper, generally accepts MS's codepage names.

    Some windows apllication encode domain name with some specific multi-
    lingual encoding. For example, if you configured IE to use UTF-8,
    then domain names are encoded with UTF-8. UTF-8 is one of proposed
    DNS encoding, but DNS server may expect another encoding.
    
    For those cases, mDN wrapper accept program specific encoding as
    local encoding.  These program specific local encoding should be
    marked in registry.
    
    Program specific registry setting will placed under

        HKEY_LOCAL_MACHINE\SOFTWARE\JPNIC\MDN\PerProg
	HKEY_CURRENT_USER\SOFTWARE\JPNIC\MDN\PerProg
    
    using program name (executable file name) as key.  For example,
    setting specific to Internet Explore, it executable name is 
    "IEXPLORE", will plcaed at

        HKEY_LOCAL_MACHINE\SOFTWARE\JPNIC\MDN\PerProg\IEXPLORE

    Local encoding name will specified with registry value (REG_SZ) of 
    "Encoding".  This name must be one of encoding names which '
    recognize.libmdn'

        Registry Value "Encoding"   REG_SZ
	
	    Encoding name of application program encodes, if it is not
            system's default encoding.

3. Setup and Configuration

    mDN Wrapper, as standard installation, wraps WINSOCK DLL on 
    application's directory.  For this installation, mDN Wrapper
    presents setup program and configuration program.
    
    NOTE:   You can also install mDN wrapper DLLs to wrap WINSOCK at
            system directory.  But this installations is very dangerous.
	    You should try it at your own risk.

3.1. Setup Program

    To install mDN wrapper, run "setup.exe".  Setup program will do:
    
    Install Files
    
        Copy mDN wrapper files (DLL, Program EXE, etc) into diretory
	
	    "\Program Files\JPONIC\mDN Wrapper"

        This directory may be changed on setup sequence.

    Registry setting

        Setup program will create keys and values under registry:
	
	    "HKEY_LOCAL_MACHINES\Software\JPNIC\MDN"

        Encoding        REG_SZ  "RACE"
	
	    Name of DNS encoding.  Default value is "RACE", which is
            current candidate for DNS encoding.  This value may be
            changed with registry editor.

        PerProg         KEY
	
	    Under this key, mDN wrapper set program specific values. mDN
            wrapper uses program's executable name as key, and put
            values under that key.
	    
	    PerProg\<progname>\Where    REG_DWORD Encoding Position
	    PerProg\>progname>\Encoding REG_SZ    Local Encoding Name

            Configuration program set local encpoding name.  "Where"
            value is usually not required in standard installation.  If
            you installed mDN wrapper in system directory, chanage
            "Where" values to fit your environment.

    Creating ICON
    
        Setup program will create program icon for mDN wrapper's
        configuration program, and put it into "Start Menu".  You can
        start configuration program with it.
	   
3.2. Configuration Program

    Configuration program is a tool for wrap specific program, or unwrap
    programs.  If you start "Configuration Program", you'll get window
    link this.

    +---+-------------------------------------------------+---+---+---+
    |   | mDN Wrapper - Configuration                     | _ | O | X |
    +---+-------------------------------------------------+---+---+---+
    |          mDN Wrapper Configuration Program version X.X          |
    +-----------------------------------------------------------------+
    |                  Wrapped Program                    +---------+ |
    | +---------------------------------------------+---+ | Wrap..  | |
    | |                                             | A | +---------+ |
    | |                                             +---+ +---------+ |
    | |                                             |   | | Unwrap..| |
    | |                                             |   | +---------+ |
    | |                                             |   | +---------+ |
    | |                                             |   | |UnwrapAll| |
    | |                                             |   | +---------+ |
    | |                                             |   | +---------+ |
    | |                                             |   | |RewrapAll| |
    | |                                             |   | +---------+ |
    | |                                             |   | +---------+ |
    | |                                             |   | |  Log..  | |
    | |                                             |   | +---------+ |
    | |                                             |   | +---------+ |
    | |                                             +---+ |Advanced.| |
    | |                                             | V | +---------+ |
    | +---+-------------------------------------+---+---+ +---------+ |
    | | < |                                     | > |     |  Exit   | |
    | +---+-------------------------------------+---+     +---------+ |
    +-----------------------------------------------------------------+

    Listbox contains list of current wrapped programs.  It initially
    empty.  
    
    To wrap a program, press button "wrap".  You'll get following dialog.
    
    +---+-------------------------------------------------+---+---+---+
    |   | mDN Wrapper - Wrap Executable                   | _ | O | X |
    +---+-------------------------------------------------+---+---+---+
    |           +----------------------------------------+ +--------+ |
    |  Program: |                                        | |Browse..| |
    |           +----------------------------------------+ +--------+ |
    |           +----------+                                          |
    | Encoding: |          |  o Default  o UTF-8                      |
    |           +----------+                                          |
    +-----------------------------------------------------------------+
    |                                           +--------+ +--------+ |
    |                                           |  Wrap  | | Cancel | |
    |                                           +--------+ +--------+ |
    +-----------------------------------------------------------------+

    First, enter program (executable name with full path) or browse
    wrapping exectable from file browser. Then set local encoding of
    that program.  Usually use "Default" as local encoding. If target
    program uses internationalized encoding, then specify "UFT-8". 
    Finally, put "wrap" button to wrap specified program with given
    encoding. Wrapped program will be listed in listbox of the first
    window.

    When you install a new version of mDN Wrapper, you have to re-wrap
    your programs in order to update DLLs used for wrapping.  "Rewrap
    all" button is provided for this purpose.  Just press the button,
    and all the currently wrapped programs will be re-wrapped.

    To unwrap a program, press button "unwrap".  You'll get following 
    confirmating dialog.
    
    +---+-------------------------------------------------+---+---+---+
    |   | mDN Wrapper - Unwrap Executable                 | _ | O | X |
    +---+-------------------------------------------------+---+---+---+
    |           +---------------------------------------------------+ |
    | Program:  |                                                   | |
    |           +---------------------------------------------------+ |
    +-----------------------------------------------------------------+
    |                                           +--------+ +--------+ |
    |                                           | Unwrap | | Cancel | |
    |                                           +--------+ +--------+ |
    +-----------------------------------------------------------------+

    If you unwrap a program, the program will be vanished from listbox
    of the first window.

    Also "Unwrap all" button is provided to unwrap all the programs
    that are currently wrapped.

    To configure logging, press button "log".  You'll get the following
    dialog.

    +---+-------------------------------------------------+---+---+---+
    |   | mDN Wrapper - Log Configuration                 | _ | O | X |
    +---+-------------------------------------------------+---+---+---+
    |    Log Level: o None o Fatal o Error o Warning o Info o Trace   |
    |                                                                 |
    |              +------------------------------------+ +---------+ |
    |     Log File:|                                    | | Browse..| |
    |              +------------------------------------+ +---------+ |
    |               +------+ +--------+                               |
    |Log Operation: | View | | Delete |                               |
    |               +------+ +--------+                               |
    +-----------------------------------------------------------------+
    |                                           +--------+ +--------+ |
    |                                           |   OK   | | Cancel | |
    |                                           +--------+ +--------+ |
    +-----------------------------------------------------------------+

    Logging level can be selected from the followings.
	None	no logging at all
	Fatal   only records fatal errors
	Error	also records non-fatal errors
	Warning	also records warning mssages
	Info	also records informational messages
	Trace	also records trace information
    Note that these levels are for log output from MDN library (libmdn).
    mDN Wrapper itself supports only off (None) and on (the rest).

    Pathname of the log file can also be specified with this dialog.

    You can view the current log file contents by pressing "View" button,
    or delete it by "Delete" button.

    Note that log level and log file configuration doesn't affect already
    running processes.

    Press "advanced" button to invoke the advanced configuration dialog.
    This dialog is for advanced users and enables customization for
    some basic parameters which normal users need not change, since
    appropriate defaults are provided.

    +---+-------------------------------------------------+---+---+---+
    |   | mDN Wrapper - Advanced Configuration            | _ | O | X |
    +---+-------------------------------------------------+---+---+---+
    |                    MDN Wrapping Mode                            |
    |  o Wrap both WINSOCK 1.1 and WINSOCK 2.0                        |
    |  o Wrap only WINSOCK 1.1                                        |
    |  o Wrap only WINSOCK 2.0                                        |
    |  o Wrap only WINSOCK 2.0 if it exists.                          |
    |    Otherwise wrap only WINSOCK 1.1                              |
    +-----------------------------------------------------------------+
    |                       MDN Configuration                         |
    |               +--------------------------------+ +----------+   |
    |  Config File: |                                | | Browse.. |   |
    |               +--------------------------------+ +----------+   |
    |               +------+                                          |
    |               | Edit |                                          |
    |               +------+                                          |
    +-----------------------------------------------------------------+
    |                                           +--------+ +--------+ |
    |                                           |   OK   | | Cancel | |
    |                                           +--------+ +--------+ |
    +-----------------------------------------------------------------+

    With the dialog users can do the following configuration.

    Wrapping Mode
	Customize wrapping mode.  Normally the default item should be
	appropriate.  Changing it to other item may help when you
	have problems.

    MDN Configuration
	Set the configuration file for multilingual domain name handling.
	By pressing "Edit" button, you can edit then contents of the file.

4. Limitations

4.1. DLL Versions

    Wrapper DLL is tightly coupled with specific DLL version. Wrapper
    DLL is expoected to export all entries including un-documented ones.
    If WINSOCK DLL version changed, mDN wrapper may not work correctly.

    Current mDN Wrapper is confirmed on
    
        WinNT4.0 SP6a   (WINSOCK 1.1 + 2.0)
        Win98           (WINSOCK 1.1 + 2.0)
	Win95 OSR2      (WINSOCK 1.1)

    But there are no assuarance for feature version of windows.

4.2. DNS, WINS, LMHOSTS

    There are three name resolving methods in windows, DNS, WINS and
    LMHOSTS. Using mDN wrapper, domain name conversion will performed 
    on all of thoses methods.  It may cause some trouble if windows 
    using WINS or LMHOSTS.  We recommend use DNS oly if you want to use
    mDN Wrapper.

4.3. Converting Names other than Domain Name

    In WINSOCK 2.0, there are generic name resolution APIs are
    introduced.
    
        WSALookupServiceBeginA
	WSALookupServiceNextA
	WSALookupServiceEnd

    They are use mainly domain name conversion now, but not limited to
    resolving domain name.  mDN wrapper hooks this API and convert
    given name anyway.  This causes some trouble if conversion name is
    not domain name.

4.4. Applications don't use these APIa

    Some applications don't use these APIs to resolving domain names.
    For example, 'nslookup' issue DNS request locally.  For these
    applications, mDN wrapper does not work.

4.5. Applications bound to specific WINSOCK DLL

    Some apllications are bound to specific DLL, not rely on standard
    DLL search path. Netscape Communicator is one of such programs. mDN
    wrapper in standard installation, cannot wrap such programs.
    
    If you want to wrap those programs, you may use installation into
    system directory.  But this installation is very dangerous, for
    it is possible that your system cannot boot again.

4.6. But 'mdnsproxy' exist

    If you have above problems with your environments, there is 
    'mdnsproxy'.  It hooks on DNS transactions, so it is free from above
    problems.  But of course, it is harder to setup, and also cannot work
    with program specific encodings, such as IE, but sometimes, works
    better than mDN Wrapper.

5. Registry Setting - Summary

5.1. Priority of Setting

    Settings of mDN Wrapper is placed on registry 
    
        Software\JPNIC\MDN
	
    under HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER.  mDN Wrapper first
    read HKEY_LOCAL_MACHINE, and if HKEY_CURRENT_USER exist, overwrite
    with this one.  Usually set HKEY_LOCAL_MACHINE only.  But if you
    need per user setting, then set HKEY_CURRENT_USER.

    Note that the configuration program reads/writes only
    HKEY_LOCAL_MACHINE.

5.2. Registry Key

    There's common settings and per program settings.
    
_Common Settings

        Software\\JPNIC\\MDN\\Where         Where convert encoding
	                    0: both WINSOCK 1.1 and WINSOCK 2.0
                            1: if WINSOCK 2.0 exist, convert at 2.0 DLL
                               if WINSOCK 1.1 only, convert at 1.1 DLL
			    2: only in WINSOCK1.1
			    3: only in WINSOCK2.0
        Software\\JPNIC\\MDN\\Encoding      DNS Encoding Name
        Software\\JPNIC\\MDN\\Normalize     Normalization Scheme
        Software\\JPNIC\\MDN\\LogLevel      Log Level
        Software\\JPNIC\\MDN\\LogFile       Log File

_Per Program Settings

    Converting position and program's local encoding may be set per
    program bases.

        Software\\JPNIC\\MDN\\PerProg\\<name>\\Where
        Software\\JPNIC\\MDN\\PerProg\\<name>\\Encoding

    If not specified,
    
        Where       0       both 1.1 DLL and 2.0 DLL
	Encoding            process's code page
