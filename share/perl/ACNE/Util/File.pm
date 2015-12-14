package ACNE::Util::File;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use JSON;

sub readJSON {
	my ($path) = @_;
	open my $fh, '<', $path;
	do { local $/; decode_json(<$fh>) };
}

sub writeJSON {
	my ($data, $path) = @_;
	open my $fh, '>', $path;
	print $fh encode_json($data);
}

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

# XXX also utime
sub touch {
	my ($path) = @_;
	open my $fh, '>>', $path;
	1;
}

1;
