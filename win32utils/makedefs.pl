# makedefs.pl
# This script goes through all of the lib header files and creates a .def file for
# each DLL for Win32. It recurses as necessary through the subdirectories
#
# This program was written by PDM. mayer@gis.net 27-Feb-2001.
#
# Search String: ^(([_a-z0-9])*( ))*prefix_[_a-z0-9]+_[a-z0-9]+( )*\(
# List of directories
#
@prefixlist = ("isc", "isccfg","dns", "isccc", "libres");
@prefixlist = ("isccc");
@iscdirlist = ("isc/include/isc","isc/win32/include/isc");
@iscprefixlist = ("isc", "isc", "cfg");

@isccfgdirlist = ("isccfg/include/isccfg");
@isccfgprefixlist = ("cfg");

@iscccdirlist = ("isccc/include/isccc");
@iscccprefixlist = ("isccc");

#@omapidirlist = ("omapi/include/omapi");
#@omapiprefixlist = ("omapi");

@dnsdirlist = ("dns/include/dns","dns/sec/dst/include/dst");
# , "dns/sec/openssl/include/openssl");
@dnsprefixlist = ("dns", "dst");

@lwresdirlist = ("lwres/include/lwres");
@lwresprefixlist = ("lwres");

# Run the changes for each directory in the directory list 

$ind = 0;
createoutfile($iscprefixlist[0]);
foreach $dir (@iscdirlist) {
   createdeffile($dir, $iscprefixlist[$ind]);
   $ind++;
}
close OUTDEFFILE;

$ind = 0;
createoutfile($isccfgprefixlist[0]);
foreach $dir (@isccfgdirlist) {
   createdeffile($dir, $isccfgprefixlist[$ind]);
   $ind++;
}
close OUTDEFFILE;

$ind = 0;
createoutfile($dnsprefixlist[0]);
foreach $dir (@dnsdirlist) {
   createdeffile($dir, $dnsprefixlist[$ind]);
   $ind++;
}
close OUTDEFFILE;

$ind = 0;
createoutfile($iscccprefixlist[0]);
foreach $dir (@iscccdirlist) {
   createdeffile($dir, $iscccprefixlist[$ind]);
   $ind++;
}
close OUTDEFFILE;

$ind = 0;
createoutfile($lwresprefixlist[0]);
foreach $dir (@lwresdirlist) {
   createdeffile($dir, $lwresprefixlist[$ind]);
   $ind++;
}
close OUTDEFFILE;

sub createdeffile {
$xdir = $_[0];

#
# Get the List of files in the directory to be processed.
#
#^(([_a-z0-9])*( ))*prefix_[_a-z]+_[a-z]+( )*\(
$prefix = $_[1];
#$xdir = "$prefix/include/$prefix";
#$pattern = "\^\( \)\*$prefix\_\[\_a\-z\]\+_\[a\-z\]\+\( \)\*\\\(";
#$pattern = "\^\(\(\[\_a\-z0\-9\]\)\*\( \)\)\*$prefix\_\[\_a\-z0\-9\]\+_\[a\-z0\-9\]\+\( \)\*\\\(";
$pattern = "\^\(\(\[\_a\-z0\-9\]\)\*\( \)\)\*\(\\*\( \)\+\)\*$prefix\_\[\_a\-z0\-9\]\+_\[a\-z0\-9\]\+\( \)\*\\\(";
#print "$pattern\n";

opendir(DIR,$xdir) || die "No Directory: $!";
@files = grep(/\.h$/i, readdir(DIR));
closedir(DIR);

foreach $filename (sort @files) {
#  print "$filename\n";

#
#
# Open the file and locate the pattern.
#
  open (HFILE, "$xdir/$filename") || die "Can't open file $filename : $!";
#
#exit;

 while (<HFILE>) {
   if(/$pattern/) {
	$func = $&;
	chop($func);
	$space = rindex($func, " ") + 1;
	if($space >= 0) {
	   $func = substr($func, $space, 100); #strip out return values
	}
	print OUTDEFFILE "$func\n";
   }
 }
# Set up the Patterns
 close(HFILE);
}
}
exit;

# This is the routine that applies the changes

# output the result to the platform specific directory.
sub createoutfile {

$outfile = "lib$_[0].def";

open (OUTDEFFILE, ">$outfile") || die "Can't open output file $outfile: $!";
print OUTDEFFILE "LIBRARY lib$_[0]\n";
print OUTDEFFILE "\n";
print OUTDEFFILE "; Exported Functions\n";
print OUTDEFFILE "EXPORTS\n";
print OUTDEFFILE "\n";

}

