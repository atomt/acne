package ACNE::Cmd::NewRenew;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use ACNE::Account;
use ACNE::Cert;
use ACNE::CA;

use Getopt::Long;
use File::Spec::Functions qw(catdir);
use HTTP::Tiny;

sub run {
	my $cmd = shift @ARGV;
	my $id  = shift @ARGV;

	my (
	  @arg_dns,
	  @arg_run,
	  $arg_ca,
	  $arg_key,
	  $arg_roll_key,
	  $arg_renew_left_days
	);

	GetOptions(
	  'dns=s'      => \@arg_dns,
	  'run=s'      => \@arg_run,
	  'ca=s'       => \$arg_ca,
	  'key=s'      => \$arg_key,
	  'roll-key!'  => \$arg_roll_key,
	  'renew-left' => \$arg_renew_left_days
	) or die "try acne help\n";

	ACNE::Common::config();
	ACNE::Common::drop_privs();

	chdir catdir(@{$config->{'system'}->{'store'}});

	my $cert = ACNE::Cert->new($id, {
	  'dns'        => \@arg_dns,
	  'run'        => \@arg_run,
	  'ca'         => $arg_ca,
	  'key'        => $arg_key,
	  'roll-key'   => $arg_roll_key,
	  'renew-left' => $arg_renew_left_days
	});

	my $ca_id      = $cert->getCAId;

	say sprintf("Using CA %s, key %s, roll-key %s (on renewals)",
	  $ca_id,
	  $cert->getKeyConf,
	  $cert->getRollKey
	);

	my $account = ACNE::Account->new;
	my $ca = ACNE::CA->new($ca_id, $account->keyInit);

	if ( !$account->registered($ca, $ca_id) ) {
		exit 1;
	}

	$cert->issue($ca);
	$cert->save;
}

1;
