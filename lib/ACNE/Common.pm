package ACNE::Common;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use Exporter 'import';
our @EXPORT_OK = qw($config);

use File::Spec::Functions qw(catfile);
use ACNE::Validator;
use ACNE::Util::File;

our @etcdir = ('', 'etc', 'acne');

my $system_validator = ACNE::Validator->new(
	'store' => {
		default   => ['', 'var', 'lib', 'acne'],
		validator => [\&ACNE::Validator::PATH]
	},
	'user' => {
		default   => 'root',
		validator => [\&ACNE::Validator::WORD]
	}
);

my $defaults_validator = ACNE::Validator->new(
	'renew-left' => {
		default   => 10,
		validator => [\&ACNE::Validator::INT, 1, 356]
	},
	'ca'         => {
		default   => 'letsencrypt',
		validator => [\&ACNE::Validator::WORD]
	},
	'key'        => {
		default   => 'rsa',
		validator => [\&ACNE::Validator::PRINTABLE],
	},
	'roll-key'   => {
		default   => 1,
		validator => [\&ACNE::Validator::BOOL]
	},
	'run'        => {
		default   => undef,
		validator => [sub {
			my @r;
			for my $c ( split(/\s+/, $_[0]) ) {
				push @r, ACNE::Validator::WORD($c);
			}
			\@r;
		}]
	}
);

my $account_validator = ACNE::Validator->new(
	# FIXME?
	'email' => {
		default => undef,
		validator => [\&ACNE::Validator::REGEX, qr/^(.+\@.+)/]
	},
	'tel' => {
		default => undef,
		validator => [\&ACNE::Validator::REGEX, qr/^([\d\+\ -]+)/]
	}
);

my $ca_validator = ACNE::Validator->new(
	# FIXME
	'acme-server' => {
		default => undef,
		validator => [\&ACNE::Validator::REGEX, qr/^(.+)/]
	},
	'directory' => {
		default => undef,
		validator => [\&ACNE::Validator::REGEX, qr/^(.+)/]
	}
);

# Will be pluginified
my $challenge_validator = ACNE::Validator->new(
	'acmeroot' => {
		default   => ['', 'var', 'lib', 'acne', 'httpchallenge'],
		validator => [\&ACNE::Validator::PATH]
	}
);

our $config;

sub keyValidator {
	my $input = defined $_[0] ? $_[0] : 'rsa';
	my ($type, $arg) = split(/:/, $input, 2);

	if ( $type eq 'rsa' ) {
		$arg = defined $arg ? ACNE::Validator::INT($arg, 1024, 8192) : 3072;
	}
	elsif ( $type eq 'ecdsa' ) {
		$arg = defined $arg ? ACNE::Validator::REGEX($arg, qr/^(secp224r1|secp256r1|prime256v1|secp384r1|secp521r1)$/) : 'prime256v1';
		if ( $arg eq 'secp256r1' ) {
			$arg = 'prime256v1';
		}
	}
	else {
		die "Supported key types are: rsa and ecdsa\n";
	}

	($type, $arg);
}

sub config {
	my (@errors, $discard);
	my $fp = catfile(@etcdir, 'config');
	my ($raw, $err) = ACNE::Util::File::readPairsStruct($fp)
	  if -e $fp;

	# Shipped CAs
	$raw->{'ca'}->{'letsencrypt'}->{'directory'} = 'https://acme-v01.api.letsencrypt.org/directory'
	  if !exists $raw->{'ca'}->{'letsencrypt'}->{'directory'};
	$raw->{'ca'}->{'letsencrypt-staging'}->{'directory'} = 'https://acme-staging.api.letsencrypt.org/directory'
	  if !exists $raw->{'ca'}->{'letsencrypt-staging'}->{'directory'};

	# Verify each grouping and remove when done, if we have any left at the end, bail.
	my $system = delete $raw->{'system'};
	($config->{'system'}, $err) = $system_validator->process($system);
	push @errors, "in section \"system\"\n", @$err if $err;
	($discard, $err) = $system_validator->unknown_keys($system);
	push @errors, "in section \"system\"\n", @$err if $err;

	my $defaults = delete $raw->{'defaults'};
	($config->{'defaults'}, $err) = $defaults_validator->process($defaults);
	push @errors, "in section \"defaults\"\n", @$err if $err;
	($discard, $err) = $defaults_validator->unknown_keys($defaults);
	push @errors, "in section \"defaults\"\n", @$err if $err;

	my $account = delete $raw->{'account'};
	($config->{'account'}, $err) = $account_validator->process($account);
	push @errors, "in section \"account\"\n", @$err if $err;
	($discard, $err) = $account_validator->unknown_keys($account);
	push @errors, "in section \"account\"\n", @$err if $err;

	$config->{'ca'} = {};
	while ( my ($k, $v) = each %{$raw->{'ca'}} ) {
		my $ca = delete $raw->{'ca'}->{$k};
		($config->{'ca'}->{$k}, $err) = $ca_validator->process($ca);
		push @errors, "in section \"ca\"\n", @$err if $err;
		($discard, $err) = $ca_validator->unknown_keys($ca);
		push @errors, "in section \"ca\"\n", @$err if $err;
	}
	delete $raw->{'ca'};

	# for now challenge.http01fs is hardcoded
	my $http01fs = delete $raw->{'challenge'}->{'http01fs'};
	($config->{'challenge'}->{'http01fs'}, $err) = $challenge_validator->process($http01fs);
	push @errors, "in section \"challenge\"\n", @$err if $err;
	($discard, $err) = $challenge_validator->unknown_keys($http01fs);
	push @errors, "in section \"challenge\"\n", @$err if $err;
	push @errors, "unsupported challenge \"$_\"\n" for keys %{$raw->{'challenge'}};
	delete $raw->{'challenge'};

	push @errors, "unknown section \"$_\"\n"
	  for keys %$raw;

	if ( @errors ) {
		die "Errors loading configuration file $fp\n", @errors;
	}

	1;
}

# FIXME too much NIH and maybe bad place
sub drop_privs {
	use English qw(-no_match_vars);
	my $user = $config->{'system'}->{'user'};

	my ($uid, $gid, $home, $shell) = (getpwnam($user))[2,3,7,8];
	if ( !defined $uid or !defined $gid ) {
		die "Could not find uid and gid of configured system.user $user\n"
	}
	my @gids = getgrouplist($user, $gid);

	# Consider allowing setuid operation later
	if ( ($UID != 0 and $EUID != 0) and ($UID != $uid and $EUID != $uid) ) {
		die "Not invoked as either root or configured user - aborting\n";
	}

	if ( $UID == $uid and $EUID == $uid ) {
		return;
	}

	# Actually change, twice, and in a special order, because some
	# platforms do not close all the doors back to previous uid otherwise
	($GID) = @gids; $EGID = join(' ', @gids); $EUID = $UID = $uid;
	($GID) = @gids; $EGID = join(' ', @gids); $EUID = $UID = $uid;

	if ( $UID ne $uid or $EUID ne $uid ) {
		die "Changing uid to $uid ($user) failed\n";
	}

	if ( (split(' ', $GID))[0] ne $gid ) {
		die "Changing gid to $gid failed\n";
	}

	$ENV{'USER'}    = $user;
	$ENV{'LOGNAME'} = $user;
	$ENV{'HOME'}    = $home;
	$ENV{'SHELL'}   = $shell;

	1;
}

# Emulate Linux/BSD getgrouplist, slowly, iterating over all groups
sub getgrouplist {
	my ($username, $gid) = @_;
	my @groups = ($gid);
	while ( my ($name, $comment, $ggid, $rawgroups) = getgrent ) {
		next if $ggid == $gid;
		push @groups, $ggid
		  if grep { $_ eq $username } split /\s/, $rawgroups;
	}
	@groups;
}

1;
