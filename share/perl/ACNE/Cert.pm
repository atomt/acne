package ACNE::Cert;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::Common;
use ACNE::Util::File;
use ACNE::Crypto::RSA;

use File::Spec::Functions;

sub _new {
	my ($class, $id, $conf) = @_;

	# Load defaults and ca config early to get early feedback.
	my $defaults = ACNE::Util::File::readPairs(catfile(@ACNE::Common::etcdir, 'defaults'));
	my $combined; { my %tmp = (%$defaults, %$conf); $combined = \%tmp };
	
	# Make sure CA and account is always saved to the cert json
	# regardless if specified on command line.
	$conf->{ca}      = $combined->{ca};
	$conf->{account} = $combined->{account};

	bless {
	  id       => $id,
	  dir      => catdir(@ACNE::Common::libdir, 'db', $id),
	  conf     => $conf,
	  defaults => $defaults,
	  combined => $combined
	} => $class;
}

# Create new object
sub new {
	my ($class, $id, $conf) = @_;

	# Clean config (removes options not specified)
	while ( my($key, $val) = each %$conf ) {
		delete $conf->{$key} if !defined $val;
	}

	my $s = _new(@_);

	die "$id already exists\n"
	  if -d $s->{'dir'};

	$s;
}

# Load config from db and return new object
sub load {
	my ($class, $id) = @_;
	my $conf_fp = catfile(@ACNE::Common::libdir, 'db', $id, 'config.json');
	_new(@_, ACNE::Util::File::readJSON($conf_fp));
}

sub getId        { $_[0]->{'id'}; };
sub getCAId      { $_[0]->{'combined'}->{'ca'}; }
sub getAccountId { $_[0]->{'combined'}->{'account'}; }
sub getKeyConf   { $_[0]->{'combined'}->{'key'}; }
sub getRollKey   { $_[0]->{'combined'}->{'roll-key'}; }

sub pkeyCreate {
	my ($conf) = @_;
	my $ret;

	my ($type, $arg) = split(/:/, $conf, 2);
	if ( $type eq 'rsa' ) {
		$ret = ACNE::Crypto::RSA->new($arg);
	}
	else {
		die "Unsupported key type \"$type\"\n";
	}

	$ret;
}


1;