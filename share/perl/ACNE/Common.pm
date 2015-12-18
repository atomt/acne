package ACNE::Common;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use Exporter 'import';
our @EXPORT_OK = qw($config);

use File::Spec::Functions qw(catfile);
use ACNE::Validator;

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
		default   => 'letsencrypt-staging',
		validator => [\&ACNE::Validator::WORD]
	},
	'account'    => {
		default   => 'default',
		validator => [\&ACNE::Validator::WORD]
	},
	'key'        => {
		default   => 'rsa:3072',
		validator => [\&ACNE::Validator::REGEX, qr/^(rsa:\w+)$/]
	},
	'roll-key'   => {
		default   => 1,
		validator => [\&ACNE::Validator::BOOL]
	},
	'for'        => {
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
	}
);

my $ca_validator = ACNE::Validator->new(
	# FIXME
	'acme-server' => {
		validator => [\&ACNE::Validator::REGEX, qr/^(.+)/]
	}
);

# Will be pluginified
my $challenge_validator = ACNE::Validator->new(
	'acmeroot' => {
		validator => [\&ACNE::Validator::PATH]
	}
);

our $config;

sub config {
	my @errors;
	my $fp = catfile(@etcdir, 'config');
	my ($raw, $err) = ACNE::Util::File::readPairsStruct($fp);

	# Shipped CAs
	$raw->{'ca'}->{'letsencrypt'}->{'acme-server'} = 'acme-v01.api.letsencrypt.org'
	  if !exists $raw->{'ca'}->{'letsencrypt'}->{'acme-server'};
	$raw->{'ca'}->{'letsencrypt-staging'}->{'acme-server'} = 'acme-staging.api.letsencrypt.org'
	  if !exists $raw->{'ca'}->{'letsencrypt-staging'}->{'acme-server'};

	# Default empty subgroups
	$raw->{'account'}->{'default'} = {}
	  if !exists $raw->{'account'}->{'default'};

	# Verify each grouping and remove when done, if we have any left at the end, bail.
	($config->{'system'}, $err) = $system_validator->process(delete $raw->{'system'});
	push @errors, "in system section\n", @$err if $err;

	($config->{'defaults'}, $err) = $defaults_validator->process(delete $raw->{'defaults'});
	push @errors, "in section \"default\"\n", @$err if $err;

	$config->{'ca'} = {};
	while ( my ($k, $v) = each %{$raw->{'ca'}} ) {
		($config->{'ca'}->{$k}, $err) = $ca_validator->process(delete $raw->{'ca'}->{$k});
		push @errors, "in section \"ca\"\n", @$err if $err;
	}
	delete $raw->{'ca'};

	$config->{'account'} = {};
	while ( my ($k, $v) = each %{$raw->{'account'}} ) {
		($config->{'account'}->{$k}, $err) = $account_validator->process(delete $raw->{'account'}->{$k});
		push @errors, "in section \"account\"\n", @$err if $err;
	}
	delete $raw->{'account'};

	# for now challenge.http01fs is hardcoded
	($config->{'challenge'}->{'http01fs'}, $err) = $challenge_validator->process(delete $raw->{'challenge'}->{'http01fs'});
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

1;