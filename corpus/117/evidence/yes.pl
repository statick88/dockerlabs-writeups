use strict; use warnings;
my $H = '$y$j9T$tRCuWr1iQy3bpfVGn9UgM.$zgL23sFzked4H5n8vXBuACUQ9vDduVFxlYTP222P2h.';
# POSITIVE CONTROL: find the plaintext of a hash we generate ourselves with the same scheme.
my $ctrl_salt = '$y$j9T$PE117ctrlAAAAAAAAAAAAAAAAAA.';
my $mk = "PE117CTRLMARKER";
my $ch = crypt($mk, $ctrl_salt);
my $ok = (defined $ch) && ($ch =~ /^\$y\$/) && (crypt($mk,$ch) eq $ch);
print "POSITIVE_CONTROL yescrypt_roundtrip=" . ($ok?"true":"false") . " scheme=" . substr((defined $ch?$ch:""),0,4) . "\n";
exit 2 unless $ok;
print "ORACLE_FIRED=true\n";
open(my $fh,'<','dictionary.txt') or die; my @d=<$fh>; close $fh; chomp @d;
my @extra = qw(dumbass pressi pressenter Pressenter hacker root toor echo Echo chronos enter);
my $n=0; my $f=0;
for my $w (@d, @extra) { next if $w eq ''; $n++; if (crypt($w,$H) eq $H) { print "CRACK user=enter password=$w candidate=$n\n"; $f++; } }
print "TOTAL_TRIED=$n MATCHES=$f\n";
