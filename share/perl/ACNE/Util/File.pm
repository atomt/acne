package ACNE::Util::File;

use 5.014;
use warnings;
use autodie;

use IO::File;

sub readPairs {
	my ($path) = @_;
	my $ret = {};
	my $fh = IO::File->new($path, 'r')
	  or die "$path, $!\n";
	while ( my $line = <$fh> ) {
		chomp($line);
		my ($key, $val) = split(/\s+/, $line, 2);
		$ret->{$key} = $val;
	}
	$ret;
}

1;