# Microsoft Developer Studio Generated NMAKE File, Based on makekeyset.dsp
!IF "$(CFG)" == ""
CFG=makekeyset - Win32 Debug
!MESSAGE No configuration specified. Defaulting to makekeyset - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "makekeyset - Win32 Release" && "$(CFG)" != "makekeyset - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "makekeyset.mak" CFG="makekeyset - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "makekeyset - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "makekeyset - Win32 Debug" (based on "Win32 (x86) Console Application")
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

!IF  "$(CFG)" == "makekeyset - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release

!IF "$(RECURSE)" == "0" 

ALL : "..\..\..\Build\Release\dnssec-makekeyset.exe"

!ELSE 

ALL : "libisc - Win32 Release" "libdns - Win32 Release" "..\..\..\Build\Release\dnssec-makekeyset.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libdns - Win32 ReleaseCLEAN" "libisc - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\dnssec-makekeyset.obj"
	-@erase "$(INTDIR)\dnssectool.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "..\..\..\Build\Release\dnssec-makekeyset.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "./" /I "../../../" /I "../../../lib/isc/win32" /I "../../../lib/isc/win32/include" /I "../../../lib/isc/include" /I "../../../lib/dns/include" /I "../../../lib/dns/sec/dst/include" /D "NDEBUG" /D "__STDC__" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\makekeyset.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\makekeyset.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=user32.lib advapi32.lib ../../../lib/isc/win32/Release/libisc.lib ../../../lib/dns/win32/Release/libdns.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\dnssec-makekeyset.pdb" /machine:I386 /out:"../../../Build/Release/dnssec-makekeyset.exe" 
LINK32_OBJS= \
	"$(INTDIR)\dnssec-makekeyset.obj" \
	"$(INTDIR)\dnssectool.obj" \
	"..\..\..\lib\dns\win32\Release\libdns.lib" \
	"..\..\..\lib\isc\win32\Release\libisc.lib"

"..\..\..\Build\Release\dnssec-makekeyset.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "makekeyset - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "..\..\..\Build\Debug\dnssec-makekeyset.exe" "$(OUTDIR)\makekeyset.bsc"

!ELSE 

ALL : "libisc - Win32 Debug" "libdns - Win32 Debug" "..\..\..\Build\Debug\dnssec-makekeyset.exe" "$(OUTDIR)\makekeyset.bsc"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libdns - Win32 DebugCLEAN" "libisc - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\dnssec-makekeyset.obj"
	-@erase "$(INTDIR)\dnssec-makekeyset.sbr"
	-@erase "$(INTDIR)\dnssectool.obj"
	-@erase "$(INTDIR)\dnssectool.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\dnssec-makekeyset.pdb"
	-@erase "$(OUTDIR)\makekeyset.bsc"
	-@erase "..\..\..\Build\Debug\dnssec-makekeyset.exe"
	-@erase "..\..\..\Build\Debug\dnssec-makekeyset.ilk"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "./" /I "../../../" /I "../../../lib/isc/win32" /I "../../../lib/isc/win32/include" /I "../../../lib/isc/include" /I "../../../lib/dns/include" /I "../../../lib/dns/sec/dst/include" /D "_DEBUG" /D "WIN32" /D "__STDC__" /D "_CONSOLE" /D "_MBCS" /FR"$(INTDIR)\\" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\makekeyset.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\dnssec-makekeyset.sbr" \
	"$(INTDIR)\dnssectool.sbr"

"$(OUTDIR)\makekeyset.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=user32.lib advapi32.lib ../../../lib/isc/win32/Debug/libisc.lib ../../../lib/dns/win32/Debug/libdns.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\dnssec-makekeyset.pdb" /debug /machine:I386 /out:"../../../Build/Debug/dnssec-makekeyset.exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\dnssec-makekeyset.obj" \
	"$(INTDIR)\dnssectool.obj" \
	"..\..\..\lib\dns\win32\Debug\libdns.lib" \
	"..\..\..\lib\isc\win32\Debug\libisc.lib"

"..\..\..\Build\Debug\dnssec-makekeyset.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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
!IF EXISTS("makekeyset.dep")
!INCLUDE "makekeyset.dep"
!ELSE 
!MESSAGE Warning: cannot find "makekeyset.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "makekeyset - Win32 Release" || "$(CFG)" == "makekeyset - Win32 Debug"
SOURCE="..\dnssec-makekeyset.c"

!IF  "$(CFG)" == "makekeyset - Win32 Release"


"$(INTDIR)\dnssec-makekeyset.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "makekeyset - Win32 Debug"


"$(INTDIR)\dnssec-makekeyset.obj"	"$(INTDIR)\dnssec-makekeyset.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\dnssectool.c

!IF  "$(CFG)" == "makekeyset - Win32 Release"


"$(INTDIR)\dnssectool.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "makekeyset - Win32 Debug"


"$(INTDIR)\dnssectool.obj"	"$(INTDIR)\dnssectool.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

!IF  "$(CFG)" == "makekeyset - Win32 Release"

"libdns - Win32 Release" : 
   cd "\bind9.2.0\lib\dns\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libdns.mak CFG="libdns - Win32 Release" 
   cd "..\..\..\bin\dnssec\win32"

"libdns - Win32 ReleaseCLEAN" : 
   cd "\bind9.2.0\lib\dns\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libdns.mak CFG="libdns - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\..\bin\dnssec\win32"

!ELSEIF  "$(CFG)" == "makekeyset - Win32 Debug"

"libdns - Win32 Debug" : 
   cd "\bind9.2.0\lib\dns\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libdns.mak CFG="libdns - Win32 Debug" 
   cd "..\..\..\bin\dnssec\win32"

"libdns - Win32 DebugCLEAN" : 
   cd "\bind9.2.0\lib\dns\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libdns.mak CFG="libdns - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\..\bin\dnssec\win32"

!ENDIF 

!IF  "$(CFG)" == "makekeyset - Win32 Release"

"libisc - Win32 Release" : 
   cd "\bind9.2.0\lib\isc\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libisc.mak CFG="libisc - Win32 Release" 
   cd "..\..\..\bin\dnssec\win32"

"libisc - Win32 ReleaseCLEAN" : 
   cd "\bind9.2.0\lib\isc\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\libisc.mak CFG="libisc - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\..\bin\dnssec\win32"

!ELSEIF  "$(CFG)" == "makekeyset - Win32 Debug"

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

