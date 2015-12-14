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
	$defaults->{for} = [$defaults->{for}]; # FIXME
	my $combined; { my %tmp = (%$defaults, %$conf); $combined = \%tmp };
	
	# Make sure CA, account and for is always saved to the cert json
	# regardless if specified on command line.
	$conf->{ca}      = $combined->{ca};
	$conf->{account} = $combined->{account};
	$conf->{for}     = $combined->{for};

	bless {
	  id       => $id,
	  dir      => catdir(@ACNE::Common::libdir, 'cert', $id),
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
	delete $conf->{'for'} if @{$conf->{'for'}} == 0;

	my $s = _new(@_);

	die "certificate ID \"$id\" already exists\n"
	  if -d $s->{'dir'};

	$s;
}

# Load config from db and return new object
sub load {
	my ($class, $id) = @_;
	my $conf_fp = catfile(@ACNE::Common::libdir, 'cert', $id, 'config.json');
	_new(@_, ACNE::Util::File::readJSON($conf_fp));
}

# Write cert files to cert db
sub save {
	my ($s) = @_;
	my $id  = $s->{'id'};
	my $dir = $s->{'dir'};

	my $conf_fp = catfile(@ACNE::Common::libdir, 'cert', $id, 'config.json');

	if ( ! -e $dir ) {
		mkdir $dir, 0700;
	}

	ACNE::Util::File::writeJSON($s->{'conf'}, $conf_fp);
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