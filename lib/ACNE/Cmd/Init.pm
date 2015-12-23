package ACNE::Cmd::Init;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use File::Spec::Functions qw(catdir);
use English qw(-no_match_vars);

sub run {
	ACNE::Common::config();

	my $store    = catdir(@{$config->{'system'}->{'store'}});
	my $acmeroot = catdir(@{$config->{'challenge'}->{'http01fs'}->{'acmeroot'}});
	my $user     = $config->{'system'}->{'user'};

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

# Not using perl built-ins is a little silly, but -p and -R is so much easier.
sub mkdirv {
	my ($fp, $perms) = @_;
	-e $fp ? say "$fp already exists." : systemv('mkdir', '-p', '-m', $perms, $fp);
}

sub systemv {
	say 'run: ', join ' ', @_;
	system(@_);
}

1;
