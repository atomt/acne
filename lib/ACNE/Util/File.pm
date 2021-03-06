package ACNE::Util::File;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use JSON::PP;
use File::Spec::Functions qw(catfile);

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

		if ( exists $ret->{$k} ) {
			my $_v = $ret->{$k};
			if ( ref $_v eq '' ) {
				$_v = [$_v];
			}
			push @$_v, $v;
			$v = $_v;
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

sub touch {
	my ($path, $time) = @_;
	open my $fh, '>>', $path;
#	utime $time, $time, $fh; # undef sets "now"
	1;
}

sub statDirectoryContents {
	my ($dir) = @_;
	my @ret;
	opendir(my $dh, $dir);
	while ( my $entry = readdir $dh ) {
		my $fp = catfile($dir, $entry);
		my @stat = stat($fp);
		warn "Could not stat() $fp: $!" if @stat == 0;
		push @ret, { 'name' => $entry, 'mtime' => $stat[9] };
	}

	return @ret;
}

1;
