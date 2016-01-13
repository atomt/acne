package ACNE::Validator;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use Carp qw(croak);
use File::Spec::Functions qw(splitdir);

sub WORD {
	state $re = qr/^([\w\-]+)$/;
	my $out;

	die 'input "', printable($_[0]), '" is not a word', "\n"
	  if !(($out) = $_[0] =~ $re);

	$out;
};

sub PRINTABLE {
	state $re = qr/^(\p{PosixPrint}+)$/x;
	my $out;

	die "input contains non-printable characters\n"
	  if !(($out) = $_[0] =~ $re);

	$out;
}

sub INT {
	my ($in, $min, $max) = @_;
	state $re = qr/^(\d+)$/;
	my $out;

	die 'input "', printable($in), '" is not numeric', "\n"
	  if !(($out) = $in =~ $re);

	die "input \"$in\" is below allowed range ($in <= $min)\n"
	  if defined $min && $out <= $min;

	die "input \"$in\" is above allowed range ($in >= $max)\n"
	  if defined $max && $out >= $max;

	int($out);
};

sub REGEX {
	my ($in, $re) = @_;
	if ( my @r = $in =~ $re ) {
		return @r == 1 ? $r[0] : \@r;
	}

	die 'input "', printable($in), '" failed regex ', $re, "\n";
};

sub BOOL {
	my %table = ( on => 1, yes => 1, true => 1, off => 0, no => 0, false => 0 );
	exists $table{$_[0]} ? $table{$_[0]} : die "bool value has to one of: " . join(' ', sort keys %table) .  "\n";
};

sub PATH {
	my @p = splitdir($_[0]);
	\@p;
};

# validator => [$ACNE::Validator::ENUM, { a => 1, b => 1 }]
sub ENUM {
	my ($in, $table) = @_;
	exists $table->{$in} ? $table->{$in} : die "enum value has to one of: " . join(' ', sort keys %$table) .  "\n";
};

sub new {
	my ($class, %args) = @_;
	bless \%args, $class;
}

# FIXME we probably want to work on a copy of $data or dont delete and
# do a reverse check to find unknown keys
sub process {
	my ($s, $data) = @_;
	my @errors;
	my $ret = {};

	if ( defined $data ) {
		croak "Bad input, expected hashref"
		  if ref $data ne 'HASH';
	}
	else {
		$data = {};
	}

	while ( my ($k, $v) = each %$s ) {
		my $multiple  = $v->{'multiple'};
		my @validator = @{$v->{'validator'}};
		my $callback  = shift @validator;

		if ( my $in = delete $data->{$k} ) {
			$ret->{$k} = eval {
				my $ret;

				if ( $multiple ) {
					$ret = [];
					if ( ref $in ne 'ARRAY' && ref $in ne '' ) {
						die "input not a list or scalar\n";
					}
					$in = ref $in eq '' ? [$in] : $in;

					for ( @$in ) {
						eval { push @$ret, $callback->($_, @validator) };
						push @errors, "key \"$k\": $@" if $@;
					}
				}
				else {
					if ( ref $in ne '' ) {
						die "input not a scalar value\n";
					}
					$ret = $callback->($in, @validator);
				}

				$ret;
			};

			push @errors, "key \"$k\": $@" if $@;
		}
		else {
			if ( exists $v->{'default'} ) {
				$ret->{$k} = $v->{'default'};
			}
			else {
				push @errors, "key $k missing\n";
			}
		}

	}

	push @errors, 'unknown key "' . printable($_) . '"' . "\n"
	  for keys %$data;

	# Golang style error handling - return what we have ;-)
	if ( wantarray ) {
		return ($ret, @errors ? \@errors : undef);
	}

	# Traditional fuck-all
	die @errors if @errors;
	$ret;
}


sub printable {
	state $re = qr/[^\p{PosixPrint}]/x;
	$_[0] =~ s/$re/#/g;
	$_[0];
}

1;
