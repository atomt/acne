package ACNE::CA;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::Common qw($config);
use ACME::Client;

# Load config and pass on to ACME::Client
sub new {
	my ($class, $id, $pkey) = @_;

	my $conf = $config->{'ca'}->{$id}
	  or die "Specified CA \"$id\" has no valid configuration\n";

	ACME::Client->new(
	  pkey    => $pkey,
	  address => $conf->{'acme-server'}
	);
}

1;