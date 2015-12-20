package ACNE::Cmd::Init;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use File::Spec::Functions qw(catdir);
use English qw(-no_match_vars);

sub run {
	ACNE::Common::config();

	my $store = catdir(@{$config->{'system'}->{'store'}});
	my $user  = $config->{'system'}->{'user'};

	say 'Setting up Acne store to work with current configuration';
	say '';

	die "Insufficient privilieges, acne init requires root\n"
	  if $UID != 0;

	# Get user info
	my ($uid, $gid) = (getpwnam($user))[2,3];
	if ( !defined $uid or !defined $gid ) {
		die "Could not find uid and gid of configured system.user $user\n"
	}
	say "Configured user $user has uid $uid and gid $gid";

	# Set up system.store
	# Not using perl built-ins is a little silly, but -p and -R is so much easier.
	say "Creating system.store $store";
	-e $store ? say "system.store $store already exists." : systemv('mkdir', '-p', '-m', '0750', $store);
	systemv('chmod', '0750', $store);
	systemv('chown', '-R', $uid . ':' . $gid, $store);

	say '';
	say 'Acne should be ready for use.';
}

sub systemv {
	say 'run: ', join ' ', @_;
	system(@_);
}

1;