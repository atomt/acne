package ACNE::Util::File;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use JSON::PP;

my $re_comments   = qr!#.*$!;
my $re_whitespace = qr!(^\s+|\s+$)!;
my $re_data       = qr!^([\w\.-]+)\s+(.+)$!x;

sub readJSON {
	my ($path) = @_;
	open my $fh, '<', $path;
	do { local $/; decode_json(<$fh>) };
}

sub writeJSON { writeStr(encode_json($_[0]), $_[1]) }

sub writeStr {
	my ($data, $path) = @_;
	my $tmp = $path . '.tmp'; # FIXME, use a random hidden file
	open my $fh, '>', $tmp;
	print $fh $data;
	undef $fh;
	rename $tmp, $path;
}

sub readPairsStruct {
	my $ret = {};
	my ($in, $errors) = readPairs(@_);

	state $re_split = qr!\.!;

	while ( my ($k, $v) = each %$in ) {
		my @components = split($re_split, $k);
		my $components_i = scalar @components - 1;

		my $leaf = $ret;
		while ( my ($index, $component) = each @components ) {
			if ( $components_i == $index ) {
				$leaf->{$component} = $v;
			}
			elsif ( my $h = $leaf->{$component} ) {
				$leaf = $h;
			}
			else {
				my $new = {};
				$leaf->{$component} = $new;
				$leaf = $new;
			}
		}
	}

	# Golang style error handling - return what we have ;-)
	if ( wantarray ) {
		return ($ret, $errors);
	}

	die @$errors if $errors;
	$ret;
}

sub readPairs {
	my ($path, $_allowed) = @_;
	my $ret = {};
	my @errors;

	# Flip allowed into a lookup hash
	my %allowed = map { $_ => 1 } @$_allowed
	  if defined $_allowed;

	open my $fh, '<', $path;
	while ( my $line = <$fh> ) {
		chomp($line);

		$line =~ s/$re_comments//;
		$line =~ s/$re_whitespace//g;
		next if $line eq '';

		my ($k, $v) = ($line =~ $re_data);

		if ( !defined $k ) {
			push @errors, "line $. do not make any sense\n";
			next;
		}

		if ( %allowed && !exists $allowed{$k} ) {
			push @errors, "key \"$k\" on line $. do not match any allowed keywords\n";
			next;
		}

		$ret->{$k} = $v;
	}

	# Golang style error handling - return what we have ;-)
	if ( wantarray ) {
		return ($ret, @errors ? \@errors : undef);
	}

	die @errors if @errors;
	$ret;
}

# XXX also utime
sub touch {
	my ($path) = @_;
	open my $fh, '>>', $path;
	1;
}

1;
