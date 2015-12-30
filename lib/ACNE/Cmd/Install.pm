package ACNE::Cmd::Install;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use ACNE::Cert;
use ACNE::Validator;

use Getopt::Long;
use File::Spec::Functions qw(catdir);

sub run {
	my $cmd = shift @ARGV;

	my $arg_help;
	GetOptions(
	  'help' => \$arg_help
	) or usage_err();

	if ( $arg_help ) {
		usage();
	}

	if ( @ARGV == 0 ) {
		say STDERR 'No certificates specified on command line';
		usage_err();
	}

	ACNE::Common::config();
	ACNE::Common::drop_privs();

	chdir catdir(@{$config->{'system'}->{'store'}});

	$_ = ACNE::Validator::WORD($_) for @ARGV;

	for my $id ( @ARGV ) {
		say "Installing $id";
		eval {
			my $cert = ACNE::Cert->load($id);
			$cert->activate;
		};
		if ( $@ ) {
			print STDERR "$id FAIL! $@";
		}
	}

	ACNE::Cert::_runpostinst();
}

sub usage_err {
	say STDERR 'Try \'acne install --help\' for more information.';
	exit 1;
}

sub usage {
    say 'Usage: acne install <certname1> [<certname2> ..]';
	say '';
	say 'Re-installs already issued certificate. Useful if something went wrong';
	say 'with certificate installation during new or renew';
    exit 0;
}

1;
