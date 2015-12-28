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

	my $arg_help;
	GetOptions(
	  'help' => \$arg_help
	) or usage(1);

	if ( $arg_help ) {
		usage(0);
	}

	if ( $cmd eq 'renew-auto' ) {
		if ( @ARGV > 0 ) {
			say STDERR 'Error: renew-auto takes no certificate names';
			usage(1);
		}
	}
	else {
		if ( @ARGV == 0 ) {
			say STDERR 'Error: No certificates specified on command line';
			usage(1);
		}
	}

	ACNE::Common::config();
	ACNE::Common::drop_privs();

	chdir catdir(@{$config->{'system'}->{'store'}});

	my %ca;
	my @loaded;
	my @selected;

	if ( $cmd eq 'renew-auto' ) {
		@selected = ACNE::Cert::_findautorenews();
	}
	else {
		@selected = @ARGV;
	}

	my $account = ACNE::Account->new;

	# Load all certs and their CAs, and run pre-flight to catch errors early
	say 'Certificates selected for renewal';
	say ' ', $_ for @selected;

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
		}
	}

	say '';
	say "** Running postinst hooks **";
	ACNE::Cert::_runpostinst();
}


sub usage {
	my ($exitval) = @_;
	my $fd = $exitval ? *STDERR : *STDOUT;
	if ( $cmd eq 'renew-auto' ) {
		say $fd 'Usage: acne renew-auto';
	}
	else {
		say $fd 'Usage: acne renew <cert> [<cert2> ..]';
	}
    exit $exitval;
}

1;
