package ACNE::Cmd::New;

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
	  $arg_renew_left_days,
	  $arg_no_run
	);

	GetOptions(
	  'dns=s'      => \@arg_dns,
	  'run=s'      => \@arg_run,
	  'ca=s'       => \$arg_ca,
	  'key=s'      => \$arg_key,
	  'roll-key!'  => \$arg_roll_key,
	  'renew-left' => \$arg_renew_left_days,
	  'no-run'     => \$arg_no_run
	) or die "try acne help\n";

	if ( @arg_run and $arg_no_run ) {
		die "--run and --no-run together does not make sense; aborting.\n";
	}

	if ( @arg_dns == 0 ) {
		die "at least one -d hostname (--dns) argument must be specified\n";
	}

	ACNE::Common::config();
	ACNE::Common::drop_privs();

	chdir catdir(@{$config->{'system'}->{'store'}});

	my $cert = ACNE::Cert->new($id, {
	  'dns'        => \@arg_dns,
	  'run'        => \@arg_run,
	  'ca'         => $arg_ca,
	  'key'        => $arg_key,
	  'roll-key'   => $arg_roll_key,
	  'renew-left' => $arg_renew_left_days,
	  'no-run'     => $arg_no_run
	});

	my $ca_id      = $cert->getCAId;
	my $run        = $cert->getRun;

	say sprintf("Using CA %s, run %s, key %s, roll-key %s (on renewals)",
	  $ca_id,
	  $run ? join(' ', @$run) : 'none',
	  $cert->getKeyConf,
	  $cert->getRollKey
	);

	my $account = ACNE::Account->new;
	my $ca = ACNE::CA->new($ca_id, $account->keyInit);

	if ( !$account->registered($ca_id) ) {
		exit 1;
	}

	$cert->issue($ca);
	$cert->save;
	ACNE::Cert::_runpostinst();
}

1;
