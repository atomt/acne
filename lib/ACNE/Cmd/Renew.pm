package ACNE::Cmd::Renew;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use ACNE::Cert;
use ACNE::CA;
use ACNE::Validator;

use Getopt::Long;
use File::Spec::Functions qw(catdir);

my $cmd;
sub run {
	$cmd = shift @ARGV;
	my $exitcode = 0;

	my ($arg_cron, $arg_help);
	GetOptions(
	  'cron' => \$arg_cron,
	  'help' => \$arg_help
	) or usage_err();

	if ( $arg_help ) {
		usage();
	}

	if ( $cmd eq 'renew-auto' ) {
		if ( @ARGV > 0 ) {
			say STDERR 'No extra arguments allowed.';
			usage_err();
		}
	}
	else {
		if ( $arg_cron ) {
			say STDERR 'Unknown option: cron';
			usage_err();
		}

		if ( @ARGV == 0 ) {
			say STDERR 'No certificate names specified.';
			usage_err();
		}
	}

	ACNE::Common::config();
	ACNE::Common::drop_privs();

	chdir catdir(@{$config->{'system'}->{'store'}});


	my @selected;

	if ( $cmd eq 'renew-auto' ) {
		@selected = ACNE::Cert::_findautorenews();
	}
	else {
		@selected = @ARGV;
	}

	$_ = ACNE::Validator::WORD($_) for @selected;

	# Load all certs and their CAs, and run pre-flight to catch errors early
	if ( !$arg_cron ) {
		if ( @selected ) {
			say 'Certificates selected for renewal: ' . join('', @selected);
		}
		else {
			say 'No certificates selected';
		}
	}

	if ( @selected == 0 ) {
		exit 0;
	}

	my %ca;
	my @loaded;
	for my $id ( @selected ) {
		eval {
			my $cert = ACNE::Cert->load($id);
			my $ca_id = $cert->getCAId;
			if ( !exists $ca{$ca_id} ) {
				my $_ca = ACNE::CA->new($ca_id);
				$_ca->initialize;
				if ( !$_ca->registered_db ) {
					die;
				}

				$ca{$ca_id} = $_ca;
			}
			push @loaded, $cert;
		};
		if ( $@ ) {
			say STDOUT '';
			say STDERR 'ERROR!! Unable to load ', $id;
			print STDERR $@;
			say STDERR 'Skipping ', $id;
			$exitcode = 1;
		}
	}

	my @checked;
	for my $cert ( @loaded ) {
		my $id = $cert->getId;
		eval {
			$cert->preflight;
			push @checked, $cert;
		};
		if ( $@ ) {
			say STDOUT '';
			say STDERR 'ERROR!! Unable to pre-flight test ', $id;
			print STDERR $@;
			say STDERR 'Skipping ', $id;
			$exitcode = 1;
		}
	}

	# Renew and install
	for my $cert ( @checked ) {
		my $id    = $cert->getId;
		my $ca_id = $cert->getCAId;
		my $dns   = $cert->getDNS;
		my $run   = $cert->getRun;

		say '';
		say "** Renewing certificate $id **";
		say ' Authority ', $ca_id;
		say ' Names ', join(', ', @$dns);
		say ' Key ', $cert->getKeyConf;
		say ' Roll key ', $cert->getRollKey ? 'Yes' : 'No';
		say ' Run ', $run ? join(' ', @$run) : 'none';
		say '';

		my $ca = $ca{$ca_id};
		eval {
			$cert->order($ca);
			$cert->issue($ca);
			$cert->save;
			$cert->activate;

			say "Certificate expires ", scalar localtime($cert->getNotAfter), " GMT"; # ;)
			say "Automatic renew after ", scalar localtime($cert->getRenewAfter), " GMT";

		};
		if ( $@ ) {
			say STDOUT '';
			say STDERR 'ERROR!! Unable to process ', $id;
			print STDERR $@;
			say STDERR 'Skipping ', $id;
			$exitcode = 1;
		}
		say '';
	}

	ACNE::Cert::_runpostinst();

	exit $exitcode;
}

sub usage_err {
	say STDERR 'Try \'acne ', $cmd, ' --help\' for more information.';
	exit 1;
}

sub usage {
	if ( $cmd eq 'renew-auto' ) {
		say 'Usage: acne renew-auto [--cron]';
		say '';
		say 'Automatically renews certificates getting close to their expiry time';
		say '';
		say 'Options:';
		say '';
		say ' --cron';
		say '   Keeps it quiet unless there are certificates to process';
		say '';
	}
	else {
		say 'Usage: acne renew <certname1> [<certname2> ..]';
		say '';
		say 'Renews specified certificates.';
	}
    exit 0;
}

1;
