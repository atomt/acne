package ACNE::Util::File;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);


# XXX filter comments, blank lines, etc.
sub readPairs {
	my ($path) = @_;
	my $ret = {};
	open my $fh, '<', $path;
	while ( my $line = <$fh> ) {
		chomp($line);
		my ($key, $val) = split(/\s+/, $line, 2);
		$ret->{$key} = $val;
	}
	$ret;
}

1;
