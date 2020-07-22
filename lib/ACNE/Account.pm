package ACNE::Account;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::Common qw($config);
use ACNE::Util::File;
use ACNE::Crypto::RSA;

use File::Spec::Functions qw(catdir catfile);

sub new {
	my ($class) = @_;
	my $conf = $config->{'account'}
	  or die "Account has no valid configuration\n";
	my $dir = catdir(@{$config->{'system'}->{'store'}}, 'account', 'default');

	my $s = bless {
	  dir  => $dir,
	  conf => $conf,
	  pkey => undef
	} => $class;

	$s;
}

sub getPkey  { $_[0]->{'pkey'}; }

sub keyInit {
	my ($s) = @_;
	my $id  = $s->{'id'};
	my $dir = $s->{'dir'};

	my $pkey_fp = catfile($dir, 'privkey.pem');

	if ( ! -e $dir ) {
		mkdir $dir, 0700;
	}

	# Load or generate our key
	my $pkey;
	if ( -e $pkey_fp ) {
		$pkey = ACNE::Crypto::RSA->load($pkey_fp);
	}
	else {
		say "New account, generating account private key";
		$pkey = ACNE::Crypto::RSA->generate_key(4096);
		$pkey->save($pkey_fp, 0600);
		say "Account private key generation complete";
	}

	$s->{'pkey'} = $pkey;
	$pkey;
}

sub tos {
	my ($s, $ca_id) = @_;
	my $tos_fp = catfile($s->{'dir'}, 'agreement.' . $ca_id);
	if ( ! -e $tos_fp ) {
		return;
	}
	my $tos = do { local $/; open my $fh, '<', $tos_fp; <$fh> };
}

sub kid {
	my ($s, $ca_id) = @_;
	my $fp = catfile($s->{'dir'}, 'location.'   . $ca_id);
	if ( -e $fp ) {
		return do { local $/; open my $fh, '<', $fp; <$fh> };
	}
	return;
}

sub _registered {
	my ($s, $ca_id) = @_;
	-e catfile($s->{'dir'}, 'location.'   . $ca_id);
}

# If this account is marked registered for specified CA
sub registered {
	my ($s, $ca_id) = @_;
	my $dir = $s->{'dir'};

	if ( ! $s->_registered($ca_id) ) {
		say '';
		say 'Account has not been registered with this Certificate Authority';
		say "Use this command to register: acne account $ca_id";
		say '';

		return;
	}

	1;
}

# Register account at CA
sub ca_register {
	my ($s, $ca, $ca_id) = @_;
	my $dir     = $s->{'dir'};
	my $tos_fp  = catfile($dir, 'agreement.' . $ca_id);
	my $loc_fp  = catfile($dir, 'location.' . $ca_id);
	my $conf    = $s->{'conf'};
	my $email   = $conf->{'email'};
	my $tel     = $conf->{'tel'};

	# CA request
	my ($created, $location) = $ca->new_reg(email => $email, tel => $tel);

	say '';
	say $created ? 'Account created.' : 'Account already exists.';
	say '';

	# Record account location, also serves as a registered flag
	ACNE::Util::File::writeStr($location, $loc_fp);
	if ( my $ca_tos = $ca->tos() ) {
		ACNE::Util::File::writeStr($ca->tos, $tos_fp);
	}

	1;
}

sub ca_update {
	my ($s, $ca, $ca_id) = @_;
	my $dir     = $s->{'dir'};
	my $conf    = $s->{'conf'};
	my $email   = $conf->{'email'};
	my $tel     = $conf->{'tel'};

	# Find update URI created during ca_register
	my $loc_fp  = catfile($dir, 'location.'   . $ca_id);
	my $loc = do { local $/; open my $fh, '<', $loc_fp; <$fh> };

	$ca->reg($loc,
	  agreement => 1,
	  email     => $email,
	  tel       => $tel
	);

	say '';
	say 'Account updated at authority ', $ca_id;
	say '';
}

1;
