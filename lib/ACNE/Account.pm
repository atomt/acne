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
	-e catfile($s->{'dir'}, 'registered.' . $ca_id);
}

# Register account at CA
sub register {
	my ($s, $ca, $ca_id) = @_;
	my $dir   = $s->{'dir'};
	my $email = $s->{'conf'}->{'email'};

	my $contact;
	if ( $email ) {
		$contact = [ 'mailto:' . $email ];
	}

	$ca->new_reg(
		'agreement' => 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf',
		'contact'   => $contact
	);

	ACNE::Util::File::touch(catfile($dir, 'registered.' . $ca_id));
}

1;
