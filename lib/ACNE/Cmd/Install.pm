package ACNE::Cmd::Install;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use ACNE::Cert;

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

	if ( @ARGV == 0 ) {
		say STDERR 'Error: No certificates specified on command line';
		usage(1);
	}

	ACNE::Common::config();
	ACNE::Common::drop_privs();

	chdir catdir(@{$config->{'system'}->{'store'}});

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

sub usage {
    my ($exitval) = @_;
    my $fd = $exitval ? *STDERR : *STDOUT;
    say $fd 'Usage: acne install <cert> [<cert2> ..]';
    exit $exitval;
}

1;
