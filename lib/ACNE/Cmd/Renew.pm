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

sub run {
	my $cmd = shift @ARGV;

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

	for my $cert_id ( @selected ) {
		my $cert = ACNE::Cert->load($cert_id);
		my $ca_id = $cert->getCAId;
		if ( !exists $ca{$ca_id} ) {
			if ( !$account->registered($ca_id) ) {
				die;
			}

			$ca{$ca_id} = ACNE::CA->new($ca_id, $account->keyInit);
		}
		push @loaded, $cert;
	}

	say '';
	say '** Running pre-flight tests **';
	for my $cert ( @loaded ) {
		say $cert->getId;
		$cert->preflight;
	}

	# Renew and install
	for my $cert ( @loaded ) {
		my $id = $cert->getId;
		my $ca_id = $cert->getCAId;

		say '';
		say "** Renewing certificate $id **";
		say "Certificate Authority is $ca_id";

		my $ca = $ca{$ca_id};
		eval {
			say "Authorizing domains";
			$cert->authorize($ca);

			say "Issuing certificate";
			$cert->issue($ca);
			$cert->save;
			say "Issued certificate expires ", scalar localtime($cert->getNotAfter), " GMT"; # ;)
			say "Automatic renew after ", scalar localtime($cert->getRenewAfter), " GMT";

			say "Installing certificate";
			$cert->activate;
		};
		if ( $@ ) {
			print STDERR "$id FAIL! $@";
		}
	}

	say '';
	say "** Running postinst hooks **";
	ACNE::Cert::_runpostinst();
}


sub usage {
    my ($exitval) = @_;
    my $fd = $exitval ? *STDERR : *STDOUT;
    say $fd 'Usage: acne renew <cert> [<cert2> ..]';
    exit $exitval;
}

1;
