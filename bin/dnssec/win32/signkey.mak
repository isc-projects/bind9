# Microsoft Developer Studio Generated NMAKE File, Based on signkey.dsp
!IF "$(CFG)" == ""
CFG=signkey - Win32 Debug
!MESSAGE No configuration specified. Defaulting to signkey - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "signkey - Win32 Release" && "$(CFG)" != "signkey - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "signkey.mak" CFG="signkey - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "signkey - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "signkey - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "signkey - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release

!IF "$(RECURSE)" == "0" 

ALL : "..\..\..\Build\Release\dnssec-signkey.exe"

!ELSE 

ALL : "libisc - Win32 Release" "libdns - Win32 Release" "..\..\..\Build\Release\dnssec-signkey.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libdns - Win32 ReleaseCLEAN" "libisc - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\dnssec-signkey.obj"
	-@erase "$(INTDIR)\dnssectool.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "..\..\..\Build\Release\dnssec-signkey.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "./" /I "../../../" /I "../../../lib/isc/win32" /I "../../../lib/isc/win32/include" /I "../../../lib/isc/include" /I "../../../lib/dns/include" /I "../../../lib/dns/sec/dst/include" /D "NDEBUG" /D "__STDC__" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\signkey.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\signkey.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=user32.lib advapi32.lib ../../../lib/isc/win32/Release/libisc.lib ../../../lib/dns/win32/Release/libdns.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\dnssec-signkey.pdb" /machine:I386 /out:"../../../Build/Release/dnssec-signkey.exe" 
LINK32_OBJS= \
	"$(INTDIR)\dnssec-signkey.obj" \
	"$(INTDIR)\dnssectool.obj" \
	"..\..\..\lib\dns\win32\Release\libdns.lib" \
	"..\..\..\lib\isc\win32\Release\libisc.lib"

"..\..\..\Build\Release\dnssec-signkey.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "signkey - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "..\..\..\Build\Debug\dnssec-signkey.exe" "$(OUTDIR)\signkey.bsc"

!ELSE 

ALL : "libisc - Win32 Debug" "libdns - Win32 Debug" "..\..\..\Build\Debug\dnssec-signkey.exe" "$(OUTDIR)\signkey.bsc"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libdns - Win32 DebugCLEAN" "libisc - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\dnssec-signkey.obj"
	-@erase "$(INTDIR)\dnssec-signkey.sbr"
	-@erase "$(INTDIR)\dnssectool.obj"
	-@erase "$(INTDIR)\dnssectool.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\dnssec-signkey.pdb"
	-@erase "$(OUTDIR)\signkey.bsc"
	-@erase "..\..\..\Build\Debug\dnssec-signkey.exe"
	-@erase "..\..\..\Build\Debug\dnssec-signkey.ilk"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "./" /I "../../../" /I "../../../lib/isc/win32" /I "../../../lib/isc/win32/include" /I "../../../lib/isc/include" /I "../../../lib/dns/include" /I "../../../lib/dns/sec/dst/include" /D "_DEBUG" /D "WIN32" /D "__STDC__" /D "_CONSOLE" /D "_MBCS" /FR"$(INTDIR)\\" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\signkey.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\dnssec-signkey.sbr" \
	"$(INTDIR)\dnssectool.sbr"

"$(OUTDIR)\signkey.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=user32.lib advapi32.lib ../../../lib/isc/win32/Debug/libisc.lib ../../../lib/dns/win32/Debug/libdns.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\dnssec-signkey.pdb" /debug /machine:I386 /out:"../../../Build/Debug/dnssec-signkey.exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\dnssec-signkey.obj" \
	"$(INTDIR)\dnssectool.obj" \
	"..\..\..\lib\dns\win32\Debug\libdns.lib" \
	"..\..\..\lib\isc\win32\Debug\libisc.lib"

"..\..\..\Build\Debug\dnssec-signkey.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("signkey.dep")
!INCLUDE "signkey.dep"
!ELSE 
!MESSAGE Warning: cannot find "signkey.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "signkey - Win32 Release" || "$(CFG)" == "signkey - Win32 Debug"
SOURCE="..\dnssec-signkey.c"

!IF  "$(CFG)" == "signkey - Win32 Release"


"$(INTDIR)\dnssec-signkey.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "signkey - Win32 Debug"


"$(INTDIR)\dnssec-signkey.obj"	"$(INTDIR)\dnssec-signkey.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\dnssectool.c

!IF  "$(CFG)" == "signkey - Win32 Release"


"$(INTDIR)\dnssectool.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "signkey - Win32 Debug"


"$(INTDIR)\dnssectool.obj"	"$(INTDIR)\dnssectool.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

!IF  "$(CFG)" == "signkey - Win32 Release"

"libdns - Win32 Release" : 
   cd "\bind9.2.0\lib\dns\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libdns.mak CFG="libdns - Win32 Release" 
   cd "..\..\..\bin\dnssec\win32"

"libdns - Win32 ReleaseCLEAN" : 
   cd "\bind9.2.0\lib\dns\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libdns.mak CFG="libdns - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\..\bin\dnssec\win32"

!ELSEIF  "$(CFG)" == "signkey - Win32 Debug"

"libdns - Win32 Debug" : 
   cd "\bind9.2.0\lib\dns\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libdns.mak CFG="libdns - Win32 Debug" 
   cd "..\..\..\bin\dnssec\win32"

"libdns - Win32 DebugCLEAN" : 
   cd "\bind9.2.0\lib\dns\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libdns.mak CFG="libdns - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\..\bin\dnssec\win32"

!ENDIF 

!IF  "$(CFG)" == "signkey - Win32 Release"

"libisc - Win32 Release" : 
   cd "\bind9.2.0\lib\isc\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libisc.mak CFG="libisc - Win32 Release" 
   cd "..\..\..\bin\dnssec\win32"

"libisc - Win32 ReleaseCLEAN" : 
   cd "\bind9.2.0\lib\isc\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libisc.mak CFG="libisc - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\..\bin\dnssec\win32"

!ELSEIF  "$(CFG)" == "signkey - Win32 Debug"

"libisc - Win32 Debug" : 
   cd "\bind9.2.0\lib\isc\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libisc.mak CFG="libisc - Win32 Debug" 
   cd "..\..\..\bin\dnssec\win32"

"libisc - Win32 DebugCLEAN" : 
   cd "\bind9.2.0\lib\isc\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libisc.mak CFG="libisc - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\..\bin\dnssec\win32"

!ENDIF 


!ENDIF 

