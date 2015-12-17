package ACNE::Validator;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use File::Spec::Functions qw(splitdir);

sub WORD {
	my ($in) = @_;
	state $re = qr/^([\w\-]+)$/;
	my $out;

	die "input \"$in\" is not a word\n"
	  if !(($out) = $in =~ $re);

	$out;
};

sub INT {
	my ($in, $min, $max) = @_;
	state $re = qr/^(\d+)$/;
	my $out;

	die "input \"$in\" is not numeric\n"
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

	die "input \"$in\" failed regex $re\n";
};

sub BOOL {
	my %table = ( on => 1, yes => 1, true => 1, off => 0, no => 0, false => 0 );
	exists $table{$_[0]} ? $table{$_[0]} : die "bool value has to one of: " . join(' ', sort keys %table) .  "\n";
};

sub PATH {
	my @p = splitdir($_[0]);
	\@p;
};

# validator => [$ACNE::Validator::ENUM, a => 1, b => 1]
sub ENUM {
	my ($in, %table) = @_;
	exists $table{$in} ? $table{$in} : die "enum value has to one of: " . join(' ', sort keys %table) .  "\n";
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

	while ( my ($k, $v) = each %$s ) {
		my @validator = @{$v->{'validator'}};
		#my $validator = $v->{'validator'};
		my $callback  = shift @validator;
		
		if ( my $in = delete $data->{$k} ) {
			$ret->{$k} = eval { $callback->($in, @validator) };
			push @errors, $@ if $@;
		}
		else {
			if ( exists $v->{'default'} ) {
				$ret->{$k} = $v->{'default'};
			}
			else {
				push @errors, "parameter $k missing in input\n";
			}
		}

	}

	if ( keys %$data ) {
		push @errors, "unknown key \"$_\" in input\n"
		  for keys %$data;
	}

	# Golang style error handling - return what we have ;-)
	if ( wantarray ) {
		return ($ret, @errors ? \@errors : undef);
	}

	# Traditional fuck-all
	die @errors if @errors;
	$ret;
}

1;
