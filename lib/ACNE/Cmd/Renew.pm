package ACNE::Cmd::Renew;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use ACNE::Account;
use ACNE::Cert;
use ACNE::CA;

use Getopt::Long;
use File::Spec::Functions qw(catdir);

my $cmd;
sub run {
	$cmd = shift @ARGV;
	my $exitcode = 0;

	my $arg_help;
	GetOptions(
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

	# Load all certs and their CAs, and run pre-flight to catch errors early
	say 'Certificates selected for renewal';
	say ' ', $_ for @selected;

	my $account = ACNE::Account->new;

	my %ca;
	my @loaded;
	for my $id ( @selected ) {
		eval {
			my $cert = ACNE::Cert->load($id);
			my $ca_id = $cert->getCAId;
			if ( !exists $ca{$ca_id} ) {
				if ( !$account->registered($ca_id) ) {
					die;
				}
				$ca{$ca_id} = ACNE::CA->new($ca_id, $account->keyInit);
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

	say '';
	say '** Running pre-flight tests **';
	my @checked;
	for my $cert ( @loaded ) {
		my $id = $cert->getId;
		say $id;
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
	}

	say '';
	say "** Running postinst hooks **";
	ACNE::Cert::_runpostinst();

	exit $exitcode;
}

sub usage_err {
	say STDERR 'Try \'acne ', $cmd, ' --help\' for more information.';
	exit 1;
}

sub usage {
	if ( $cmd eq 'renew-auto' ) {
		say 'Usage: acne renew-auto';
		say '';
		say 'Automatically renews certificates getting close to their expiry time';
	}
	else {
		say 'Usage: acne renew <certname1> [<certname2> ..]';
		say '';
		say 'Renews specified certificates.';
	}
    exit 0;
}

1;
