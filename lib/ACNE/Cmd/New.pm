package ACNE::Cmd::New;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use ACNE::Cert;
use ACNE::CA;
use ACNE::Validator;

use Getopt::Long;
use File::Spec::Functions qw(catdir);

sub run {
	my $cmd = shift @ARGV;

	my (
	  @arg_dns,
	  @arg_run,
	  $arg_ca,
	  $arg_key,
	  $arg_roll_key,
	  $arg_renew_left_days,
	  $arg_no_run,
	  $arg_help
	);

	GetOptions(
	  'dns=s'      => \@arg_dns,
	  'run=s'      => \@arg_run,
	  'ca=s'       => \$arg_ca,
	  'key=s'      => \$arg_key,
	  'roll-key!'  => \$arg_roll_key,
	  'renew-left' => \$arg_renew_left_days,
	  'no-run'     => \$arg_no_run,
	  'help'       => \$arg_help
	) or usage_err();
	my $id = shift @ARGV;

	if ( $arg_help ) {
		usage();
	}

	if ( !defined $id ) {
		say STDERR 'No certificate name specified.';
		usage_err();
	}

	# Parsed outputs not used here - only for validation. Esp for $arg_key
	ACNE::Validator::WORD($id);
	ACNE::Common::keyValidator($arg_key);

	if ( @arg_run and $arg_no_run ) {
		say STDERR '--run and --no-run together does not make sense.';
		usage_err();
	}

	if ( @arg_dns == 0 ) {
		say STDERR 'at least one -d hostname (--dns) argument must be specified';
		usage_err();
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

	my $ca = ACNE::CA->new($ca_id);

	if ( !$ca->registered_db ) {
		exit 1;
	}

	$ca->initialize;

	say "** Issuing certificate $id **";
	say ' Authority ', $ca_id;
	say ' Names ', join(', ', @arg_dns);
	say ' Key ', $cert->getKeyConf;
	say ' Roll key ', $cert->getRollKey ? 'Yes' : 'No';
	say ' Run ', $run ? join(' ', @$run) : 'none';

	say '';
	say 'Running pre-flight tests';
	$cert->preflight;

	say '';
	say "Authorizing domains";
	$cert->authorize($ca);

	say '';
	say "Issuing certificate";
	$cert->issue($ca);
	$cert->save;

	say '';
	say "Installing certificate";
	$cert->activate;

	say '';
	say "Issued certificate expires ", scalar localtime($cert->getNotAfter), " GMT";
	say "Automatic renew after ", scalar localtime($cert->getRenewAfter), " GMT";

	say '';
	say "** Running postinst hooks **";
	ACNE::Cert::_runpostinst();
}

sub usage_err {
	say STDERR 'Try \'acne new --help\' for more information.';
	exit 1;
}

sub usage {
	say 'Usage: acne new <certname> -d <domain1> [-d <domain2> ..]';
	say '';
	say 'Creates a new certificate, including issuing and installing it.';
	say '';
	say 'Options:';
	say '';
	say ' -d <domain>, --dns <domain>';
	say '   Domain name to be included in certificate. Can be specified multiple times.';
	say '';
	say 'The following options override defaults set in configuration and makes them';
	say 'sticky for the certificate.';
	say '';
	say ' --ca <name>';
	say '   Use this Certificate Authority';
	say '';
	say ' --key <keyspec>';
	say '   Key specification; example for RSA: --key rsa:4096';
	say '';
	say ' --no-roll-key';
	say '   Re-use private key on renew. Normally it is regenerated';
	say '';
	say ' --run <name>';
	say '   Hooks to run on new, install and renew. Can be specified multiple times';
	say '';
	say ' --no-run';
	say '   Do not run any hooks on new, install and renew';
	say '';
    exit 0;
}

1;
