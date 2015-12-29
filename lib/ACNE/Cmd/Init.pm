package ACNE::Cmd::Init;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use Getopt::Long;
use File::Spec::Functions qw(catdir);
use English qw(-no_match_vars);

sub run {
	my $cmd = shift @ARGV;

	my ($arg_installcron, $arg_help);
	GetOptions(
	  'install-cron' => \$arg_installcron,
	  'help'         => \$arg_help
	) or usage_err();

	if ( $arg_help ) {
		usage();
	}

	if ( @ARGV ) {
		say STDERR 'This command takes no parameters.';
		usage_err();
	}

	ACNE::Common::config();

	my $store    = catdir(@{$config->{'system'}->{'store'}});
	my $acmeroot = catdir(@{$config->{'challenge'}->{'http01fs'}->{'acmeroot'}});
	my $user     = $config->{'system'}->{'user'};

	die "Insufficient privilieges, acne init requires root\n"
	  if $UID != 0;

	if ( $arg_installcron ) {
		installcron();
		exit 0;
	}

	say 'Setting up Acne store to work with current configuration';
	say '';

	# Get user info
	my ($uid, $gid) = (getpwnam($user))[2,3];
	if ( !defined $uid or !defined $gid ) {
		die "Could not find uid and gid of configured system.user $user\n"
	}
	say "Configured user $user has uid $uid and gid $gid";

	# Set up system.store
	say "Creating system.store in $store";
	mkdirv($store, '0755');

	for my $p ( ('account', 'cert') ) {
		my $fp = catdir($store, $p);
		mkdirv($fp, '0700');
		systemv('chmod', '0700', $fp);
	}
	for my $p ( ('live', catdir('live', '.versions')) ) {
		my $fp = catdir($store, $p);
		mkdirv($fp, '0750');
		systemv('chmod', '0750', $fp);
	}

	say "Creating challenge.http10fs.acmeroot $acmeroot";
	mkdirv($acmeroot, '0755');
	systemv('chmod', '0755', $acmeroot);

	systemv('chown', '-R', $uid . ':' . $gid, $store);
	say '';
	say 'Acne should be ready for use.';
}

# Make a crontab entry with fuzzed times
sub installcron {
	use Cwd 'abs_path';
	my $min  = int(rand(60));
	my $hour = int(rand(24));
	my $bin  = abs_path($0);
	my $file = '/etc/cron.d/acne';

	say 'Installing cron.d file as ', $file;

	ACNE::Util::File::writeStr(
		"MAILTO=root\n\n$min $hour * * * root if [ -x $bin ]; then $bin renew-auto --cron; fi\n",
		$file
	);
	chmod 0644, $file;

	1;
}

# Not using perl built-ins is a little silly, but -p and -R is so much easier.
sub mkdirv {
	my ($fp, $perms) = @_;
	-e $fp ? say "$fp already exists." : systemv('mkdir', '-p', '-m', $perms, $fp);
}

sub systemv {
	say 'run: ', join ' ', @_;
	system(@_);
}

sub usage_err {
	say STDERR 'Try \'acne init --help\' for more information.';
	exit 1;
}

sub usage {
    say 'Usage: acne init';
	say '';
	say 'Sets up store according to configuration.';
    exit 0;
}

1;
