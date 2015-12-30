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

	my $s = bless {
	  dir  => catdir(@{$config->{'system'}->{'store'}}, 'account', 'default'),
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

sub _registered {
	my ($s, $ca_id) = @_;
	-e catfile($s->{'dir'}, 'location.'   . $ca_id);
}

# If this account is marked registered for specified CA
sub registered {
	my ($s, $ca_id) = @_;
	my $dir = $s->{'dir'};
	my $tosp_fp = catfile($dir, 'tospending.' . $ca_id);

	if ( -e $tosp_fp ) {
		my $tos = do { local $/; open my $fh, '<', $tosp_fp; <$fh> };
		say '';
		say 'Terms of Service is pending acceptance for this Certificate Authority';
		say "Please review $tos";
		say '';
		say "Approve it using this command: acne account $ca_id --accept-tos <the URI above>";
		say 'before issuing any certificates using this authority';
		say '';
		return;
	}

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
	my $tosp_fp = catfile($dir, 'agreement.pending.' . $ca_id);
	my $loc_fp  = catfile($dir, 'location.' . $ca_id);
	my $conf    = $s->{'conf'};
	my $email   = $conf->{'email'};
	my $tel     = $conf->{'tel'};

	# CA request
	my ($created, $location, $toslocation) = $ca->new_reg(email => $email, tel => $tel);

	say '';
	say $created ? 'Account created.' : 'Account already exists.';
	say '';

	# Record account location, also serves as a registered flag
	ACNE::Util::File::writeStr($location, $loc_fp);

	if ( $toslocation ) {
		ACNE::Util::File::writeStr($toslocation, $tosp_fp);
		say 'Certificate Authority requested acceptance of a Terms of Service located at';
		say $toslocation;
		say '';
		say "Approve it using: acne account $ca_id --accept-tos <the URI above>";
		say "before issuing any certificates using this authority";
		say '';

		return;
	}

	1;
}

sub ca_update {
	my ($s, $ca, $ca_id, $agreement) = @_;
	my $dir     = $s->{'dir'};
	my $conf    = $s->{'conf'};
	my $email   = $conf->{'email'};
	my $tel     = $conf->{'tel'};

	# Find update URI created during ca_register
	my $loc_fp  = catfile($dir, 'location.'   . $ca_id);
	my $loc = do { local $/; open my $fh, '<', $loc_fp; <$fh> };

	# Find agreement.ca_id
	# indicates prior agreement accepted by both user and CA
	my $tos_fp  = catfile($dir, 'agreement.' . $ca_id);
	my $tosp_fp = catfile($dir, 'agreement.pending.' . $ca_id);
	my $tos;
	if ( defined $agreement ) {
		$tos = $agreement;
	}
	elsif ( -e $tos_fp ) {
		$tos = do { local $/; open my $fh, '<', $tos_fp; <$fh> };
	}

	$ca->reg($loc,
	  agreement => $tos,
	  email     => $email,
	  tel       => $tel
	);

	# Update accepted agreement
	if ( $agreement ) {
		ACNE::Util::File::writeStr($agreement, $tos_fp);
		unlink $tosp_fp if -e $tosp_fp;
	}

	say '';
	say 'Account updated at authority ', $ca_id;
	say '';
}

1;
