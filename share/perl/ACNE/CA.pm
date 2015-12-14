package ACNE::CA;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::Common;
use ACME::Client;
use File::Spec::Functions;

# Load config and pass on to ACME::Client
sub new {
	my ($class, $id, $pkey) = @_;

	my $etc_fp = catdir(@ACNE::Common::etcdir, 'ca', $id);
	my $conf = _config(catfile($etc_fp, 'config'));

	ACME::Client->new(
	  pkey    => $pkey,
	  baseurl => $conf->{'acme-server'}
	);
}

sub _config {
	my ($fp) = @_;
	ACNE::Util::File::readPairs($fp);
}

1;