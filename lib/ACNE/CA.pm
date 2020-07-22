package ACNE::CA;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::Common qw($config);
use ACME::Client;

# Load config and pass on to ACME::Client
sub new {
	my ($class, $id, $account) = @_;

	my $conf = $config->{'ca'}->{$id}
	  or die "Specified CA \"$id\" has no valid configuration\n";

	my $directory  = $conf->{'directory'};
	my $acmeserver = $conf->{'acme-server'};

	if ( !defined $directory ) {
		if ( !defined $acmeserver ) {
			die "CA configuration is missing directory or acme-server\n";
		}
		$directory = 'https://' . $acmeserver . '/directory';
	}

	ACME::Client->new(
		kid       => $account->kid($id),
	  pkey      => $account->keyInit,
	  directory => $directory
	);
}

1;