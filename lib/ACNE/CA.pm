package ACNE::CA;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::Common qw($config);
use ACNE::Crypto::RSA;
use ACNE::Util::File;

use File::Spec::Functions qw(catdir catfile);

use parent qw(ACME::Client);

# Load config and pass on to ACME::Client
sub new {
	my ($class, $ca_id) = @_;

	# Get CA setup from configuration
	my $caconf = $config->{'ca'}->{$ca_id}
	  or die "Specified CA \"$ca_id\" has no valid configuration\n";

	my $directory  = $caconf->{'directory'};
	my $acmeserver = $caconf->{'acme-server'};

	if ( !defined $directory ) {
		if ( !defined $acmeserver ) {
			die "CA configuration is missing directory or acme-server\n";
		}
		$directory = 'https://' . $acmeserver . '/directory';
	}

	my $account_dir = catdir(@{$config->{'system'}->{'store'}}, 'account', $ca_id);
	my $parent = $class->SUPER::new(directory => $directory);
	$parent->{'ca_id'} = $ca_id;
	$parent->{'account_dir'} = $account_dir;
	return $parent;
}

sub id { $_[0]->{'ca_id'}; }

sub initialize {
	my ($s) = @_;
	my $pkey_fp = catfile($s->{'account_dir'}, 'privkey.pem');

	if ( !-e $pkey_fp ) {
		die "Attempted initialize without a private key";
	}

	$s->pkey_set(ACNE::Crypto::RSA->load($pkey_fp));
	$s->SUPER::initialize(@_);

	# Request kid from CA
	eval {
		my $kid = $s->newAccount(onlyReturnExisting => 1);
		$s->kid_set($kid);
		if ( $kid && !$s->registered_db ) {
			$s->registered_db_set;
		}
	};
	if ( $@ ) {
		warn $@;
	}
}

sub create_db {
	my ($s) = @_;
	my $ca  = $s->{'ca'};
	my $dir = $s->{'account_dir'};
	my $pkey_fp = catfile($dir, 'privkey.pem');

	if ( ! -e $dir ) {
		mkdir $dir, 0700;
	}

	say "New account, generating account private key";
	my $pkey = ACNE::Crypto::RSA->generate_key(4096);
	$pkey->save($pkey_fp, 0600);
	say "Account private key generation complete";

	1;
}

sub account_exists_db {
	return -e catfile($_[0]->{'account_dir'}, 'privkey.pem');
}

sub registered_db_set {
	ACNE::Util::File::touch(catfile($_[0]->{'account_dir'}, 'registered'), undef);
}

sub registered_db {
	return -e catfile($_[0]->{'account_dir'}, 'registered');
}

1;