# Microsoft Developer Studio Project File - Name="libdns" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libdns - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libdns.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libdns.mak" CFG="libdns - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libdns - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libdns - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libdns - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "libdns_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "./" /I "../../../" /I "include" /I "../include" /I "../../isc/win32" /I "../../isc/win32/include" /I "../../isc/include" /I "../../dns/sec/openssl/include" /I "../../dns/sec/dst/include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "__STDC__" /D "_MBCS" /D "_USRDLL" /D "USE_MD5" /D "OPENSSL" /D "DST_USE_PRIVATE_OPENSSL" /D "LIBDNS_EXPORTS" /YX /FD /c
# SUBTRACT CPP /X
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 user32.lib advapi32.lib ws2_32.lib ../../isc/win32/Release/libisc.lib /nologo /dll /machine:I386 /out:"../../../Build/Release/libdns.dll"

!ELSEIF  "$(CFG)" == "libdns - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "libdns_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "./" /I "../../../" /I "include" /I "../include" /I "../../isc/win32" /I "../../isc/win32/include" /I "../../isc/include" /I "../../dns/sec/openssl/include" /I "../../dns/sec/dst/include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "__STDC__" /D "_MBCS" /D "_USRDLL" /D "USE_MD5" /D "OPENSSL" /D "DST_USE_PRIVATE_OPENSSL" /D "LIBDNS_EXPORTS" /FR /YX /FD /GZ /c
# SUBTRACT CPP /X
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 user32.lib advapi32.lib ws2_32.lib ../../isc/win32/debug/libisc.lib /nologo /dll /map /debug /machine:I386 /out:"../../../Build/Debug/libdns.dll" /pdbtype:sept

!ENDIF 

# Begin Target

# Name "libdns - Win32 Release"
# Name "libdns - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Group "Main Dns Lib"

# PROP Default_Filter "c"
# Begin Source File

SOURCE=..\a6.c
# End Source File
# Begin Source File

SOURCE=..\acl.c
# End Source File
# Begin Source File

SOURCE=..\adb.c
# End Source File
# Begin Source File

SOURCE=..\byaddr.c
# End Source File
# Begin Source File

SOURCE=..\cache.c
# End Source File
# Begin Source File

SOURCE=..\callbacks.c
# End Source File
# Begin Source File

SOURCE=..\compress.c
# End Source File
# Begin Source File

SOURCE=..\db.c
# End Source File
# Begin Source File

SOURCE=..\dbiterator.c
# End Source File
# Begin Source File

SOURCE=..\dbtable.c
# End Source File
# Begin Source File

SOURCE=..\diff.c
# End Source File
# Begin Source File

SOURCE=..\dispatch.c

!IF  "$(CFG)" == "libdns - Win32 Release"

!ELSEIF  "$(CFG)" == "libdns - Win32 Debug"

# ADD CPP /I "../sec/dst/include"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\DLLMain.c
# End Source File
# Begin Source File

SOURCE=..\dnssec.c
# End Source File
# Begin Source File

SOURCE=..\forward.c
# End Source File
# Begin Source File

SOURCE=..\journal.c
# End Source File
# Begin Source File

SOURCE=..\keytable.c
# End Source File
# Begin Source File

SOURCE=..\lib.c
# End Source File
# Begin Source File

SOURCE=..\log.c
# End Source File
# Begin Source File

SOURCE=..\lookup.c
# End Source File
# Begin Source File

SOURCE=..\master.c
# End Source File
# Begin Source File

SOURCE=..\masterdump.c
# End Source File
# Begin Source File

SOURCE=..\message.c
# End Source File
# Begin Source File

SOURCE=..\name.c
# End Source File
# Begin Source File

SOURCE=..\ncache.c
# End Source File
# Begin Source File

SOURCE=..\nxt.c
# End Source File
# Begin Source File

SOURCE=..\peer.c
# End Source File
# Begin Source File

SOURCE=..\rbt.c
# End Source File
# Begin Source File

SOURCE=..\rbtdb.c
# End Source File
# Begin Source File

SOURCE=..\rbtdb64.c
# End Source File
# Begin Source File

SOURCE=..\rdata.c
# End Source File
# Begin Source File

SOURCE=..\rdatalist.c
# End Source File
# Begin Source File

SOURCE=..\rdataset.c
# End Source File
# Begin Source File

SOURCE=..\rdatasetiter.c
# End Source File
# Begin Source File

SOURCE=..\rdataslab.c
# End Source File
# Begin Source File

SOURCE=..\request.c
# End Source File
# Begin Source File

SOURCE=..\resolver.c
# End Source File
# Begin Source File

SOURCE=..\result.c
# End Source File
# Begin Source File

SOURCE=..\rootns.c
# End Source File
# Begin Source File

SOURCE=..\sdb.c
# End Source File
# Begin Source File

SOURCE=..\soa.c
# End Source File
# Begin Source File

SOURCE=..\ssu.c
# End Source File
# Begin Source File

SOURCE=..\stats.c
# End Source File
# Begin Source File

SOURCE=..\tcpmsg.c
# End Source File
# Begin Source File

SOURCE=..\time.c
# End Source File
# Begin Source File

SOURCE=..\timer.c
# End Source File
# Begin Source File

SOURCE=..\tkey.c
# End Source File
# Begin Source File

SOURCE=..\tsig.c
# End Source File
# Begin Source File

SOURCE=..\ttl.c
# End Source File
# Begin Source File

SOURCE=..\validator.c
# End Source File
# Begin Source File

SOURCE=.\version.c
# End Source File
# Begin Source File

SOURCE=..\view.c
# End Source File
# Begin Source File

SOURCE=..\xfrin.c
# End Source File
# Begin Source File

SOURCE=..\zone.c
# End Source File
# Begin Source File

SOURCE=..\zonekey.c
# End Source File
# Begin Source File

SOURCE=..\zt.c
# End Source File
# End Group
# Begin Group "dst"

# PROP Default_Filter "c"
# Begin Source File

SOURCE=..\sec\dst\dst_api.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\dst_lib.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\dst_parse.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\dst_result.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\gssapi_link.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\gssapictx.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\hmac_link.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\key.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\openssl_link.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\openssldh_link.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\openssldsa_link.c
# End Source File
# Begin Source File

SOURCE=..\sec\dst\opensslrsa_link.c
# End Source File
# End Group
# Begin Group "openssl"

# PROP Default_Filter "c"
# Begin Source File

SOURCE=..\sec\openssl\a_bitstr.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_bytes.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_enum.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_gentm.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_int.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_object.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_octet.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_print.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_set.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_type.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_utctm.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_utf8.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\a_vis.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\asn1_lib.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_add.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_asm.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_blind.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_ctx.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_div.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_err.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_exp.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_exp2.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_gcd.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_lcl.h
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_lib.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_mont.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_mul.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_prime.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_prime.h
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_print.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_rand.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_recp.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_shift.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_sqr.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\bn_word.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\buffer.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\cryptlib.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\cryptlib.h
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dh_err.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dh_gen.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dh_key.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dh_lib.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dsa_asn1.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dsa_err.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dsa_gen.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dsa_key.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dsa_lib.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dsa_ossl.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dsa_sign.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\dsa_vrf.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\err.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\ex_data.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\lhash.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\md32_common.h
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\md5_locl.h
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\mem.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\mem_dbg.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\obj_dat.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\obj_dat.h
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\obj_lib.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\rand_lib.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\rsa_chk.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\rsa_eay.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\rsa_gen.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\rsa_lib.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\rsa_none.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\rsa_oaep.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\rsa_pk1.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\rsa_sign.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\rsa_ssl.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\sha1_one.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\sha1dgst.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\sha_locl.h
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\stack.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\x_algor.c
# End Source File
# Begin Source File

SOURCE=..\sec\openssl\x_sig.c
# End Source File
# End Group
# Begin Source File

SOURCE=.\libdns.def
# End Source File
# End Target
# End Project
