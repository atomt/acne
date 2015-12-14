package ACNE::Cert;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::Common;
use ACNE::Util::File;
use ACNE::Crypto::RSA;

use JSON;
use File::Spec::Functions;

sub _new {
	my ($class, $id, $group, $conf) = @_;

	# Load defaults and ca config early to get early feedback.
	my $defaults = groupDefaults($group);
	my $combined; { my %tmp = (%$defaults, %$conf); $combined = \%tmp };
	
	# Make sure CA and account is always saved to the cert json
	$conf->{ca}      = $combined->{ca};
	$conf->{account} = $combined->{account};

	bless {
	  id       => $id,
	  conf     => $conf,
	  defaults => $defaults,
	  combined => $combined,
	  group    => $group,
	} => $class;
}

# Create new object
sub new {
	my ($class, $id, $group, $conf) = @_;

	die "$id already exists under $group\n"
	  if -d dbpath($group, $id);

	# Clean config (removes undefs)
	while ( my($key, $val) = each %$conf ) {
		delete $conf->{$key} if !defined $val;
	}

	_new(@_);
}

# Load config from db and return new object
sub load {
	my ($class, $id, $group) = @_;
	my $conf_fp = catfile(dbpath($group, $id), 'config.json');
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

# XXX validation
sub groupDefaults {
	my ($group) = @_;
	ACNE::Util::File::readPairs(catfile(@ACNE::Common::etcdir, 'group', $group, 'defaults'));
}

sub dbpath {
	my ($group, $id) = @_;
	catdir(@ACNE::Common::libdir, 'db', $group, $id);
}


1;