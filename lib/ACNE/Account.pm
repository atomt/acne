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
	  or die "Specified account has no valid configuration\n";

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
		say "Using existing private key for account";
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

# If this account is marked registered for specified CA
sub registered {
	my ($s, $ca, $ca_id) = @_;
	my $dir = $s->{'dir'};
	my $tosp_fp = catfile($dir, 'tospending.' . $ca_id);
	my $loc_fp  = catfile($dir, 'location.'   . $ca_id);

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

	if ( ! -e $loc_fp ) {
		say '';
		say 'Account has not been registered with this Certificate Authority';
		say "Use this command to register: acne account $ca_id";
		say '';

		return;
	}

	1;
}

# Register account at CA
sub register {
	my ($s, $ca, $ca_id) = @_;
	my $dir     = $s->{'dir'};
	my $tosp_fp = catfile($dir, 'tospending.' . $ca_id);
	my $loc_fp  = catfile($dir, 'location.'   . $ca_id);
	my $conf    = $s->{'conf'};
	my $email   = $conf->{'email'};
	my $tel     = $conf->{'tel'};

  # Previous run registered that a TOS has to be accepted
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

	# Already registered
	#if ( -e $loc_fp ) {
	#	return 1;
	#}

	# CA request
	my ($location, $toslocation) = $ca->new_reg(email => $email, tel => $tel);

	# Record account location, also serves as a registered flag
	open my $loc_fh, '>', $loc_fp;
	print $loc_fh $location;

	if ( $toslocation ) {
		open my $tos_fh, '>', $tosp_fp;
		print $tos_fh $toslocation;
		say '';
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

sub accept_tos {
	my ($s, $ca, $ca_id, $uri) = @_;
	my $dir     = $s->{'dir'};
	my $tosp_fp = catfile($dir, 'tospending.' . $ca_id);
	my $tos_fp  = catfile($dir, 'tos.'        . $ca_id);
	my $loc_fp  = catfile($dir, 'location.'   . $ca_id);
	my $conf    = $s->{'conf'};
	my $email   = $conf->{'email'};
	my $tel     = $conf->{'tel'};

#	my $tos = do { local $/; open my $fh, '<', $tosp_fp; <$fh> };
	my $loc = do { local $/; open my $fh, '<', $loc_fp; <$fh> };

	$ca->reg($loc, email => $email, tel => $tel, agreement => $uri);

	say '';
	say 'Status of Terms of Service agreement updated at Certificate Authority';
	say '';

	rename $tosp_fp, $tos_fp
	  if -e $tosp_fp;
}

1;
