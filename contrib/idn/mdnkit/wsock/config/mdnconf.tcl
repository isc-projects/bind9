# $Id: mdnconf.tcl,v 1.1.2.1 2002/02/08 12:16:11 marka Exp $
#
# mdnconf.tcl - configure mDN Wrapper
#

#############################################################################
#  Copyright (c) 2000 Japan Network Information Center.  All rights reserved.
#   
#  By using this file, you agree to the terms and conditions set forth bellow.
#  
#  			LICENSE TERMS AND CONDITIONS 
#  
#  The following License Terms and Conditions apply, unless a different
#  license is obtained from Japan Network Information Center ("JPNIC"),
#  a Japanese association, Kokusai-Kougyou-Kanda Bldg 6F, 2-3-4 Uchi-Kanda,
#  Chiyoda-ku, Tokyo 101-0047, Japan.
#  
#  1. Use, Modification and Redistribution (including distribution of any
#     modified or derived work) in source and/or binary forms is permitted
#     under this License Terms and Conditions.
#  
#  2. Redistribution of source code must retain the copyright notices as they
#     appear in each source code file, this License Terms and Conditions.
#  
#  3. Redistribution in binary form must reproduce the Copyright Notice,
#     this License Terms and Conditions, in the documentation and/or other
#     materials provided with the distribution.  For the purposes of binary
#     distribution the "Copyright Notice" refers to the following language:
#     "Copyright (c) Japan Network Information Center.  All rights reserved."
#  
#  4. Neither the name of JPNIC may be used to endorse or promote products
#     derived from this Software without specific prior written approval of
#     JPNIC.
#  
#  5. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY JPNIC
#     "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#     LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
#     PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL JPNIC BE LIABLE
#     FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#     CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#     SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#     BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#     WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#     OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#     ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
#  
#  6. Indemnification by Licensee
#     Any person or entities using and/or redistributing this Software under
#     this License Terms and Conditions shall defend indemnify and hold
#     harmless JPNIC from and against any and all judgements damages,
#     expenses, settlement liabilities, cost and other liabilities of any
#     kind as a result of use and redistribution of this Software or any
#     claim, suite, action, litigation or proceeding by any third party
#     arising out of or relates to this License Terms and Conditions.
#  
#  7. Governing Law, Jurisdiction and Venue
#     This License Terms and Conditions shall be governed by and and
#     construed in accordance with the law of Japan. Any person or entities
#     using and/or redistributing this Software under this License Terms and
#     Conditions hereby agrees and consent to the personal and exclusive
#     jurisdiction and venue of Tokyo District Court of Japan.
#############################################################################

global  configFile configBack
global  registryKey registryEnc registryDef
global  filesCpy filesRen filesDel

# mDNkit version
set version	"2.2.2"

set configFile  "mdnconf.lst"   ;# list of wrapped program
set configBack  "mdnconf.bak"   ;# backup of previous data

set serverKey		"HKEY_LOCAL_MACHINE\\Software\\JPNIC\\MDN"
set serverLogLevel	LogLevel
set serverLogLevelDef	-1
set serverLogLevelNone	-1
set serverLogFile	LogFile
set serverLogFileDef	{C:\mdn_wrapper.log}
set serverConfFile	ConfFile

set perprogKey		"HKEY_LOCAL_MACHINE\\Software\\JPNIC\\MDN\\PerProg\\"
set perprogEnc		Encoding
set perprogDef		Default

set logFileNameDef	mdn_wrapper.log
set confFileNameDef	mdn.conf

set filesCpy11 { "jpnicmdn.dll" "iconv.dll" "wsock32.dll" }
set filesCpy20 { "jpnicmdn.dll" "iconv.dll" "wsock32.dll" "ws2_32.dll" }
set filesRen11 { { "wsock32.dll" "wsock32o.dll" } }
set filesRen20 { { "wsock32.dll" "wsock32o.dll" } { "ws2_32.dll" "ws2_32o.dll" } }
set filesDel11 { "jpnicmdn.dll" "iconv.dll" "wsock32.dll" "wsock32o.dll" }
set filesDel20 { "jpnicmdn.dll" "iconv.dll" "wsock32.dll" "wsock32o.dll" "ws2_32.dll" "ws2_32o.dll" }

########################################################################
#
# handling pathname
#

proc    getExeName { prg } {
    set elem [file split $prg]
    set leng [expr {[llength $elem] - 1}]
    set name [lindex $elem $leng]
    set exe  [file rootname $name]
    return $exe
}

proc    getDirName { prg } {
    set dir [file dirname $prg]
    return $dir
}

########################################################################
#
# loadList / saveList
#
#   loadList - load list of wrapped executables from $configFile
#   saveList - save list of wrapped executables into $configFile
#

proc loadList {} {

    global configFile configBack

    if { [file exists $configFile] } {
        file copy -force $configFile $configBack
    }

    set aList {}
    set fd [open $configFile {CREAT RDONLY}]
    while { ! [eof $fd]} {
        set line [gets $fd]
	if { [string length $line] > 0} {
            lappend aList "$line"
        }
    }
    close $fd
    return $aList
}

proc saveList { aList } {
    global configFile
    file delete -force $configFile
    set fd [open $configFile {CREAT WRONLY}]
    foreach e $aList {
        puts $fd $e
    }
    close $fd
}

########################################################################
#
# putList / getList - set/get list to/from listbox
#

proc putList { lb aList } {
    foreach e $aList {
        $lb insert end $e
    }
}

proc getList { lb } {
    return [$lb get 0 end]
}

########################################################################
#
# checkList / appendList / deleteList - check / append / delete program from/to listbox
#

proc checkList { lb prg } {
    set cnt 0
    set lst [getList $lb]
    
    foreach n $lst {
        if { [string compare $prg $n] == 0 } {
	    incr cnt
        }
    }
    return $cnt
}

proc appendList { lb prg } {

    if {  [checkList $lb $prg] == 0 } {
        $lb insert end $prg
    }
}

proc deleteList { lb prg } {
    set cnt 0
    set lst [getList $lb]

    foreach n $lst {
        if { [string compare $n $prg] == 0 } {
	    $lb delete $cnt
        }
	incr cnt
    }
}

########################################################################
#
# registry operations
#

proc    regGetEncode { prg } {

    global  perprogKey perprogEnc perprogDef

    if { [string compare $prg "" ] == 0 } {
        return $perprogDef
    }

    global tcl_platform
    set os $tcl_platform(platform)
    if { [string compare $os "windows"] != 0 } {
        return $perprogDef
    }
    package require registry 1.0
    
    set name [getExeName $prg]
    set key $perprogKey$name

    if { [catch {set enc [registry get $key $perprogEnc]} err] } {
        return $perprogDef
    }
    if { [string compare $enc ""] == 0 } {
        return $perprogDef
    }
    return $enc
}

proc    regSetEncode { prg enc } {

    global  perprogKey perprogEnc perprogDef

    global tcl_platform
    set os $tcl_platform(platform)
    if { [string compare $os "windows"] != 0 } {
        return 1
    }

    package require registry 1.0

    set name [getExeName $prg]
    set key $perprogKey$name

    if { [string compare $enc $perprogDef] == 0 } {
        set enc ""
    }
    if { [catch {registry set $key $perprogEnc $enc sz} ] } {
        return 2 
    }
    return 0
}

proc regGetLogLevel {} {
    global serverKey serverLogLevel serverLogLevelDef
    regGetValue $serverKey $serverLogLevel $serverLogLevelDef
}

proc regSetLogLevel {level} {
    global serverKey serverLogLevel
    regSetValue $serverKey $serverLogLevel $level dword
}

proc regGetLogFile {} {
    global serverKey serverLogFile serverLogFileDef
    set file [regGetValue $serverKey $serverLogFile $serverLogFileDef]
    if {[catch {file attributes $file -longname} lfile]} {
	# Maybe $file doesn't exist (yet).  Get the longname of
	# directory portion.
	set dir [file dirname $file]
	if {[catch {file attributes $dir -longname} ldir]} {
	    set ldir $dir
	}
	set lfile [file join $ldir [file tail $file]]
    }
    file nativename $lfile
}

proc regSetLogFile {file} {
    global serverKey serverLogFile
    regSetValue $serverKey $serverLogFile [file nativename $file]
}

proc regGetConfFile {} {
    global serverKey serverConfFile
    set file [regGetValue $serverKey $serverConfFile {}]
    if {[string compare $file {}] == 0} {
	return {}
    }
    if {[catch {file attributes $file -longname} lfile]} {
	# Maybe $file doesn't exist (yet).  Get the longname of
	# directory portion.
	set dir [file dirname $file]
	if {[catch {file attributes $dir -longname} ldir]} {
	    set ldir $dir
	}
	set lfile [file join $ldir [file tail $file]]
    }
    file nativename $lfile
}

proc regSetConfFile {file} {
    global serverKey serverConfFile
    regSetValue $serverKey $serverConfFile [file nativename $file]
}

proc regGetWhere {} {
    global serverKey
    regGetValue $serverKey Where 0
}

proc regSetWhere {where} {
    global serverKey
    regSetValue $serverKey Where $where dword
}

proc regGetValue {key name default} {
    if {![isWindows]} {
	puts "--regGetValue $key $name"
        return $default
    }
    package require registry 1.0
    
    if {[catch {registry get $key $name} value]} {
        return $default
    }
    if {[string compare $value {}] == 0} {
        return $default
    }
    return $value
}

proc regSetValue {key name value {type sz}} {
    if {![isWindows]} {
	puts "--regSetValue $key $name $value"
        return 1
    }

    package require registry 1.0

    if {[catch {registry set $key $name $value $type}]} {
        return 2 
    }
    return 0
}

########################################################################
#
# install / uninstall DLL s
#

proc fileInstall { prg } {

    global env tcl_platform
    global filesCpy11 filesCpy20 filesRen11 filesRen20
    
    set pl $tcl_platform(platform)
    if { [string compare $pl "windows"] != 0 } {
        return 1
    }

    set os $tcl_platform(os)
    switch $os {
        "Windows 95" {
            set winDir $env(windir)
    	    set sysDir $winDir/system
	    set filesCpy $filesCpy11
	    set filesRen $filesRen11
	}
        "Windows 98" {
            set winDir $env(windir)
            set sysDir $winDir/system
	    set filesCpy $filesCpy20
	    set filesRen $filesRen20
        }
	default {
            set winDir $env(SystemRoot)
            set sysDir $winDir/system32
	    set filesCpy $filesCpy20
	    set filesRen $filesRen20
        }
    }

    set toDir [getDirName $prg ]

    foreach n $filesCpy {
        file copy -force $n $toDir
    }
    foreach n $filesRen {
        set src [lindex $n 0]
	set dst [lindex $n 1]
        file copy -force $sysDir/$src $toDir/$dst
    }
    return 0
}

proc fileRemove { prg } {
    
    global tcl_platform
    global filesDel11 filesDel20
    
    set pl $tcl_platform(platform)
    if { [string compare $pl "windows"] != 0 } {
        return 1
    }

    set os $tcl_platform(os)
    switch $os {
        "Windows 95" {
	    set filesDel $filesDel11
	}
        "Windows 98" {
	    set filesDel $filesDel20
        }
	default {
	    set filesDel $filesDel20
        }
    }

    set fromDir [getDirName $prg ]

    foreach n $filesDel {
        file delete -force $fromDir/$n
    }
    return 0
}

########################################################################
#
# Wrap/Unwrap program
#

proc execWrap { pw lb dlg prg enc } {

    set prgName [$prg get]
    set encName [$enc get]

    if {[string compare $prgName {}] == 0} {
	confErrorDialog $dlg "Program must be specified.\nClick \"Browse..\" button for browsing."
	return
    }
    if { [fileInstall $prgName] } {
        tk_messageBox -icon warning -type ok \
	              -title "Warning" \
	              -message "Cannot Install DLLs" \
		      -parent $dlg
        destroy $dlg
	return 1
    }
    if { [regSetEncode $prgName $encName] } {
        tk_messageBox -icon warning -type ok \
	              -title "Warning" \
	              -message "Cannot Set Encoding" \
		      -parent $dlg
        fileRemove $prgName
        destroy $dlg
	return 2
    }
    if { [checkList $lb $prgName] == 0 } {
        appendList $lb $prgName
    }
    saveList [getList $lb]
    destroy $dlg
}

proc execUnwrap { pw lb dlg prg } {

    set prgName [$prg get]
    
    if { [checkList $lb $prgName] == 1 } {
        fileRemove $prgName
    }
    deleteList $lb $prgName
    saveList [getList $lb]
    destroy $dlg
}
 
########################################################################
#
# dialog for Wrap / Unwrap
#

proc syncEncode { v i op } {
    global prgName encName
    set enc [regGetEncode $prgName]
    if { [string compare $encName $enc] != 0 } {
        set encName $enc
    }
}

proc confBrowse { p ePrg eEnc } {

    set types { 
        { "Executable" .exe }
    }

    set file [tk_getOpenFile -filetypes $types -parent $p ]

    if { [string compare $file ""] == 0 } {
        return
    }
    set enc [regGetEncode $file]
    $ePrg delete 0 end
    $ePrg insert 0 $file
}

proc confWrap { pw lb } {

    global prgName encName

    set idx [$lb curselection]
    if { [llength $idx] == 1 } {
        set prg [$lb get $idx]
    } else {
        set prg ""
    }

    set top .wrap
    toplevel $top
    grab     $top
    wm title $top "mDN Wrapper - Wrap Executable"

    frame $top.f1 -bd 1 -relief raised
    frame $top.f2 -bd 1 -relief raised
    pack $top.f1 -side top -fill x -expand on
    pack $top.f2 -side top -fill x -expand on

    frame $top.f1.f 
    pack $top.f1.f -fill both -expand on -padx 4 -pady 4

    set w $top.f1.f
    label $w.prgtitle -text "Program:"
    label $w.enctitle -text "Encoding:"

    entry $w.prgname -relief sunken -width 56 -textvariable prgName
    entry $w.encname -relief sunken -width  8 -textvariable encName
    set w_prgname $w.prgname
    set w_encname $w.encname
    button $w.browse -text "Browse.." \
                -command [list confBrowse $w $w_prgname $w_encname]

    frame $w.rbf
    radiobutton $w.rbf.encdef -text "Default" -variable encName \
	    -value "Default"
    radiobutton $w.rbf.encutf -text "UTF-8"   -variable encName \
	    -value "UTF-8"
    pack $w.rbf.encdef $w.rbf.encutf -side left -padx 4

    grid $w.prgtitle -row 0 -column 0 -sticky e
    grid $w.enctitle -row 1 -column 0 -sticky e
    grid $w.prgname  -row 0 -column 1 -sticky we -pady 4 -padx 2 -columnspan 2
    grid $w.browse   -row 0 -column 3 -sticky w  -pady 4 -padx 4 
    grid $w.encname  -row 1 -column 1 -sticky we -pady 4 -padx 2
    grid $w.rbf      -row 1 -column 2 -sticky w -padx 2
    grid columnconfig $w 1 -weight 1 -minsize 20
    grid columnconfig $w 2 -weight 2 -minsize 20

    trace variable prgName w syncEncode

    $w.prgname delete 0 end
    $w.prgname insert 0 $prg

    focus $w.prgname

    set w $top.f2
    button $w.wrap   -text "Wrap" \
                -command [list execWrap $pw $lb $top $w_prgname $w_encname]
    button $w.cancel -text "Cancel" \
                -command [list destroy $top]
    pack $w.cancel -side right -fill y -padx 12 -pady 4
    pack $w.wrap -side right -fill y -padx 12 -pady 4

    tkwait window $top
}

proc confUnwrap { pw lb } {

    set idx [$lb curselection]
    if { [llength $idx] != 1 } {
        tk_messageBox -icon warning -type ok \
	              -title "Warning" \
	              -message "first, select unwrapping executable" \
		      -parent $pw
	return 0
    }
    set prg [$lb get $idx]
    if { [string length $prg] == 0 } {
        tk_messageBox -icon warning -type ok \
	              -title "Warning" \
	              -message "first, select unwrapping executable" \
		      -parent $pw
	return 0
    }
    
    set top .unwrap
    toplevel $top
    grab     $top
    wm title $top "mDN Wrapper - Unwrap Executable"

    frame $top.f1 -bd 1 -relief raised
    frame $top.f2 -bd 1 -relief raised
    pack $top.f2 -side bottom -fill x
    pack $top.f1 -side bottom -fill x -expand on

    frame $top.f1.f
    pack $top.f1.f -padx 4 -pady 4 -fill both -expand on
    set w $top.f1.f
    label $w.prgtitle -text "Program:"
    entry $w.prgname -relief sunken -width 56 -textvariable prgName
    $w.prgname delete 0 end
    $w.prgname insert 0 $prg

    set w_prgname $w.prgname

    grid $w.prgtitle -row 0 -column 0 -sticky w
    grid $w.prgname  -row 0 -column 1 -sticky we -pady 4
    grid columnconfig $w 1 -weight 1 -minsize 20

    set w $top.f2
    button $w.wrap   -text "Unwrap" \
                -command [list execUnwrap $pw $lb $top $w_prgname]
    button $w.cancel -text "Cancel" \
                -command [list destroy $top]

    pack $w.cancel -side right -padx 12 -pady 6
    pack $w.wrap -side right -padx 12 -pady 6

    focus $w.wrap
    tkwait window $top
}

proc unwrapAll {pw lb} {
    set ans [tk_messageBox -type yesno -default no -icon question \
	    -parent $pw -title {mdnWrapper Configuration} \
	    -message {Really unwrap all programs?}]
    if {[string compare $ans yes] != 0} {
	return
    }
    foreach prog [$lb get 0 end] {
	fileRemove $prog
    }
    $lb delete 0 end
    saveList {}
}

proc rewrapAll {pw lb} {
    set ans [tk_messageBox -type yesno -default yes -icon question \
	    -parent $pw -title {mdnWrapper Configuration} \
	    -message {Really rewrap all programs?}]
    if {[string compare $ans yes] != 0} {
	return
    }
    foreach prog [$lb get 0 end] {
	fileInstall $prog
    }
}

proc confLog {pw} {
    global _logLevel _logFile

    set top .log
    catch {destroy $top}
    toplevel $top
    wm title $top "mDN Wrapper - Log Configuration"
    # wm transient $top $pw

    set _logLevel [regGetLogLevel]
    set _logFile [regGetLogFile]

    frame $top.f1 -bd 1 -relief raised
    frame $top.f2 -bd 1 -relief raised
    pack $top.f2 -side bottom -fill x
    pack $top.f1 -side top -fill both -expand on

    set w $top.f1
    label $w.lv_l -text "Log Level:"
    frame $w.lv_v
    global serverLogLevelNone
    set i 0
    foreach {lvl text} [list $serverLogLevelNone None \
	    0 Fatal 1 Error 2 Warning 3 Info 4 Trace] {
	radiobutton $w.lv_v.btn$i -text $text -value $lvl -variable _logLevel
	pack $w.lv_v.btn$i -side left -padx 3
	incr i
    }
    label $w.ld_l -text "Log File:"
    frame $w.ld_v
    entry $w.ld_v.e -width 40 -textvariable _logFile
    focus $w.ld_v.e
    button $w.ld_v.b -text "Browse.." -command [list selectLog $top $w.ld_v.e]
    pack $w.ld_v.b -side right -fill y -padx 6
    pack $w.ld_v.e -side left -fill both -expand yes
    #label $w.lo_l -text "Log Operation:"
    frame $w.lo_v
    button $w.lo_v.show -text "View" -command [list showLog $top]
    button $w.lo_v.delete -text "Delete" -command [list deleteLog $top]
    pack $w.lo_v.show $w.lo_v.delete -side left -padx 4

    grid $w.lv_l -row 0 -column 0 -sticky e -padx 4
    grid $w.ld_l -row 1 -column 0 -sticky e -padx 4
    #grid $w.lo_l -row 2 -column 0 -sticky e -padx 4
    grid $w.lv_v -row 0 -column 1 -sticky w -padx 4 -pady 4
    grid $w.ld_v -row 1 -column 1 -sticky we -padx 4 -pady 4
    grid $w.lo_v -row 2 -column 1 -sticky w -padx 4 -pady 4

    set w $top.f2
    button $w.ok -text "OK" -command [list configureLog $top]
    button $w.cancel -text "Cancel" -command [list destroy $top]
    pack $w.cancel -side right -padx 12 -pady 6
    pack $w.ok -side right -padx 12 -pady 6
}

proc configureLog {top} {
    global _logLevel _logFile

    if {$_logLevel != [regGetLogLevel] ||
        [string compare $_logFile [regGetLogFile]] != 0} {
	set dir [file dirname $_logFile]
	if {[string compare $dir {}]} {
	    if {![file exists $dir]} {
		confErrorDialog $top "Directory $dir doesn't exist"
		return
	    } elseif {![file isdirectory $dir]} {
		confErrorDialog $top "$dir is not a directory"
		return
	    }
	}
	regSetLogLevel $_logLevel
	regSetLogFile $_logFile
	tk_messageBox -type ok -default ok -icon info -parent $top \
		-title "mDN Wrapper Configuration" \
		-message "Changing log level or file does not affect already running processes."
    }
    destroy $top
}

proc selectLog {top e} {
    global logFileNameDef
    set file [tk_getSaveFile -title {mDN Wrapper Logfile Selection} \
	    -defaultextension .log \
	    -filetypes {{{Log Files} .log} {{All Files} *}} \
	    -initialfile $logFileNameDef \
	    -parent $top]
    if {[string compare $file {}]} {
	$e delete 0 end
	$e insert insert $file
    }
}
    
proc showLog {top} {
    global _logFile
    if {[catch {exec notepad.exe $_logFile &} r]} {
	confErrorDialog $top "Cannot execute notepad"
    }
}

proc deleteLog {top} {
    global _logFile
    set ans [tk_messageBox -type yesno -default no -icon question \
	    -parent $top -title "mdnWrapper Configuration" \
	    -message "Really delete $_logFile?"]
    if {[string compare $ans yes] == 0} {
	file delete $_logFile
    }
}

########################################################################
#
# dialog for advanced configuration
#

proc advancedConf {pw} {
    global normalizerList normalizerDef

    set top .adv
    catch {destroy $top}
    toplevel $top
    wm title $top "mDN Wrapper - Advanced Configuration"

    global _mdnOperation _confFile
    set _mdnOperation [regGetWhere]
    set _confFile [regGetConfFile]

    foreach f {f1 f2 f3} {
	frame $top.$f -bd 1 -relief raised
	pack $top.$f -side top -fill x
    }
    
    set f $top.f1
    label $f.lbl -text {MDN Wrapping Mode}
    set w $f.f
    frame $w
    foreach {rb val txt} [list \
	    rb1 0 {Wrap both WINSOCK 1.1 and WINSOCK 2.0} \
	    rb2 2 {Wrap only WINSOCK 1.1} \
	    rb3 3 {Wrap only WINSOCK 2.0} \
	    rb4 1 "Wrap only WINSOCK2.0 if it exists.\nOtherwise wrap only WINSOCK1.1"] {
	radiobutton $w.$rb -text $txt -variable _mdnOperation -value $val \
		-anchor w -justify left
	pack $w.$rb -side top -fill x -pady 1
    }
    pack $f.lbl -side top -fill x -pady 4
    pack $w -side top -fill both -padx 20 -pady 10

    set f $top.f2
    label $f.lbl -text {MDN Configuration}
    pack $f.lbl -side top -fill x -pady 6

    set w $f.f
    frame $w
    pack $w -side top -fill both -padx 10 -pady 6
    label $w.l1 -text {Config File:}
    #label $w.l2 -text {Config Operation:}
    entry $w.e -width 40 -textvariable _confFile
    focus $w.e
    button $w.br -text "Browse.." -command [list selectConf $top $w.e]
    button $w.b -text Edit -command [list editConf $top]
    grid $w.l1 -row 0 -column 0 -sticky e -padx 4
    #grid $w.l2 -row 1 -column 0 -sticky e -padx 4
    grid $w.e -row 0 -column 1 -sticky we -padx 4 -pady 4
    grid $w.b -row 1 -column 1 -sticky w -padx 4 -pady 4
    grid $w.br -row 0 -column 2 -sticky w -padx 4 -pady 4

    set w $top.f3
    button $w.ok -text "OK" -command [list advConf $top]
    button $w.cancel -text "Cancel" -command [list destroy $top]
    pack $w.cancel -side right -padx 12 -pady 8
    pack $w.ok -side right -padx 12 -pady 8
}

proc editConf {top} {
    global _confFile
    if {[catch {exec notepad.exe $_confFile &} r]} {
	confErrorDialog $top "Cannot execute notepad"
    }
}

proc selectConf {top e} {
    global confFileNameDef
    set file [tk_getOpenFile -title {mDN Wrapper Config File Selection} \
	    -defaultextension .conf \
	    -filetypes {{{Config Files} .conf} {{All Files} *}} \
	    -initialfile $confFileNameDef \
	    -parent $top]
    if {[string compare $file {}]} {
	$e delete 0 end
	$e insert insert $file
    }
}

proc advConf {top} {
    global _mdnOperation _confFile
    regSetWhere $_mdnOperation
    regSetConfFile $_confFile
    destroy $top
}

########################################################################
#
# utility
#

proc confErrorDialog {top message} {
    tk_messageBox -default ok -icon error -parent $top -type ok \
	    -title {mDN Wrapper Configuration Error} -message $message
}

proc isWindows {} {
    global tcl_platform
    expr {[string compare $tcl_platform(platform) "windows"] == 0}
}

########################################################################
#
# config program start here
#

wm title    . "mDN Wrapper - Configuration"
wm iconname . "mDN Wrapper - Configuration"


label .title -bd 1 -relief raised -pady 5 \
	-text "mDN Wrapper Configuration Program version $version"

frame .left -bd 1 -relief raised
frame .right -bd 1 -relief raised

frame .lst
label .lst.title -text "Wrapped Programs" -pady 3
listbox .lst.list -width 64 -height 16 -setgrid 1 \
            -xscrollcommand ".lst.xscroll set" \
            -yscrollcommand ".lst.yscroll set"
scrollbar .lst.yscroll -orient vertical   -command ".lst.list yview"
scrollbar .lst.xscroll -orient horizontal -command ".lst.list xview"
grid .lst.title   -row 0 -column 0 -columnspan 2 -sticky news
grid .lst.list    -row 1 -column 0 -sticky news
grid .lst.xscroll -row 2 -column 0 -sticky news
grid .lst.yscroll -row 1 -column 1 -sticky news
grid rowconfig .lst 1 -weight 1
grid columnconfig .lst 0 -weight 1

frame .btn
button .btn.wrap -text "Wrap.." -command [list confWrap . .lst.list]
button .btn.unwrap -text "Unwrap.." -command [list confUnwrap . .lst.list]
button .btn.unwrapall -text "Unwrap All" -command [list unwrapAll . .lst.list]
button .btn.rewrapall -text "Rewrap All" -command [list rewrapAll . .lst.list]
frame .btn.spacing1 -width 1 -height 12 -bd 0
button .btn.log -text "Log.." -command [list confLog .]
frame .btn.spacing2 -width 1 -height 12 -bd 0
button .btn.adv -text "Advanced.." -command [list advancedConf .]
button .btn.exit -text Exit -command exit
pack .btn.wrap   -side top    -fill x -pady 4
pack .btn.unwrap -side top    -fill x -pady 4
pack .btn.unwrapall -side top -fill x -pady 4
pack .btn.rewrapall -side top -fill x -pady 4
pack .btn.spacing1 -side top
pack .btn.log    -side top    -fill x -pady 4
pack .btn.spacing2 -side top
pack .btn.adv    -side top    -fill x -pady 4
pack .btn.exit   -side bottom -fill x -pady 4

pack .lst -in .left -padx 4 -pady 4 -fill both -expand on
pack .btn -in .right -padx 6 -pady 4 -fill both -expand on

pack .title -side top -fill x
pack .right -side right -fill y
pack .left -side left -fill y -expand on

#
# then set current list into listbox
#

set theList [loadList]
#saveList $theList
putList .lst.list $theList

#
########################################################################
