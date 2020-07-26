package ACNE::Cert;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::Common qw($config);
use ACNE::Util::File;
use ACNE::Util::Rand;
use ACNE::Crypto::RSA;
use ACNE::Crypto::ECDSA;
use ACNE::OpenSSL::Date;

use HTTP::Tiny;
use File::Path qw(make_path);
use File::Spec::Functions qw(catdir catfile);
use IPC::Open3;
use MIME::Base64 qw(encode_base64url);
use Digest::SHA qw(sha256);

# post{inst,rm}s to run after many certs processed
my %postinst;
my %postrm;

sub _new {
	my ($class, $id, $conf) = @_;

	# Load defaults and ca config early to get early feedback.
	my $defaults = $config->{'defaults'};
	my $combined = do { my %tmp = (%$defaults, %$conf); \%tmp };
	delete $combined->{'run'} if $combined->{'no-run'};

	# Make sure CA is always saved to the cert json regardless if
	# specified on command line.
	$conf->{ca}  = $combined->{ca};

	my ($keytype, $keyarg) = ACNE::Common::keyValidator($combined->{'key'});

	bless {
	  id         => $id,
	  dir        => catdir(@{$config->{'system'}->{'store'}}, 'cert', $id),
	  conf       => $conf,
	  keytype    => $keytype,
	  keyarg     => $keyarg,
	  chain      => undef,
	  pkey       => undef,
	  location   => undef,
	  notafter   => undef,
	  renew      => undef,
	  tested     => [],
	  authorized => [],
		order      => undef,
	  defaults   => $defaults,
	  combined   => $combined
	} => $class;
}

# Create new object
sub new {
	my ($class, $id, $conf) = @_;

	# Clean config (removes options not specified)
	while ( my($key, $val) = each %$conf ) {
		delete $conf->{$key} if !defined $val;
	}
	delete $conf->{'run'} if @{$conf->{'run'}} == 0;

	my $s = _new(@_);
	my $dir = $s->{'dir'};

	if ( ! -e $dir ) {
		mkdir $dir, 0700;
	}

	die "Certificate ID \"$id\" already exists\n"
	  if -e catfile($dir, 'cert.pem');

	$s;
}

# Load config from db and return new object
# FIXME allow for setting new key, for and renew parameters
# FIXME use configured store...
sub load {
	my ($class, $id) = @_;
	my $dir         = catdir(@{$config->{'system'}->{'store'}}, 'cert', $id);
	my $conf_fp     = catfile($dir, 'config.json');
	my $chain_fp    = catfile($dir, 'chain.json');
	my $key_fp      = catfile($dir, 'key.pem');
	my $loc_fp      = catfile($dir, 'location');
	my $notafter_fp = catfile($dir, 'notafter');
	my $renew_fp    = catfile($dir, 'renewafter');

	if ( ! -e $dir ) {
		die "not found in store\n";
	}

	my $conf = ACNE::Util::File::readJSON($conf_fp);
	my $s = _new($class, $id, $conf);

	my $chain = ACNE::Util::File::readJSON($chain_fp);
	# Needs untainting even though we wrote it :)
	for my $c ( @$chain ) {
		if ( $c =~ /^([\w\s\r\n-_=]+)$/ ) {
			$c = $1;
		}
		else {
			die "$chain_fp looks wonky";
		}
	}
	$s->{'chain'} = $chain;

	if ( -e $loc_fp ) {
		$s->{'location'} = do { local $/; open my $fh, '<', $loc_fp; <$fh> };
	}
	$s->{'notafter'} = do { local $/; open my $fh, '<', $notafter_fp; <$fh> };
	$s->{'renew'} = do { local $/; open my $fh, '<', $renew_fp; <$fh> };


	$s;
}

# Write cert files to cert db
sub save {
	my ($s) = @_;
	my $id    = $s->{'id'};
	my $dir   = $s->{'dir'};
	my @chain = @{$s->{'chain'}};

	my $conf_fp      = catfile($dir, 'config.json');
	my $chain_fp     = catfile($dir, 'chain.json');
	my $oconf_new_fp = catfile($dir, 'new-csr.conf');
	my $oconf_fp     = catfile($dir, 'csr.conf');
	my $key_new_fp   = catfile($dir, 'new-key.pem');
	my $key_fp       = catfile($dir, 'key.pem');
	my $loc_fp       = catfile($dir, 'location');
	my $notafter_fp  = catfile($dir, 'notafter');
	my $renew_fp     = catfile($dir, 'renewafter');

	if ( ! -e $dir ) {
		mkdir $dir, 0700;
	}

	# Save config, key and certs to store
	ACNE::Util::File::writeJSON($s->{'conf'}, $conf_fp);
	ACNE::Util::File::writeJSON(\@chain, $chain_fp);
	if ( my $loc = $s->{'location'} ) {
		ACNE::Util::File::writeStr($loc, $loc_fp);
	}
	ACNE::Util::File::writeStr($s->{'notafter'}, $notafter_fp);
	ACNE::Util::File::writeStr($s->{'renew'}, $renew_fp);
	rename $key_new_fp, $key_fp     if -e $key_new_fp;
	rename $oconf_new_fp, $oconf_fp if -e $oconf_new_fp;

	1;
}

# Keep a history using a sha digest of the chain in the directory.
# A symlink points from the place deamons look.
#
# We use symlink + rename over the old symlink for atomicity.
#
# While the way certs and keys gets read seperately in deamons makes the
# atomicity imperfect, its for free and reduces the window.
#
# live/<name> -> live/.versions/<name>/<sha>/
#
sub activate {
	my ($s) = @_;
	my $id      = $s->{'id'};
	my $dbdir   = $s->{'dir'};
	my $pkey    = $s->{'pkey'};
	my @chain   = @{$s->{'chain'}};
	my $run     = $s->{'combined'}->{'run'};
	my $norun   = $s->{'combined'}->{'no-run'};
	my $c_store = $config->{'system'}->{'store'};
	my $sha     = encode_base64url(sha256(join('', @chain)));

	my $livedir   = catdir(@$c_store, 'live', '.versions', $id, $sha);
	my $livedir_r = catdir('.versions', $id, $sha);
	my $livesym   = catfile(@$c_store, 'live', $id);
	my $livesym_t = catfile(@$c_store, 'live', $id . '.new');

	make_path $livedir, { mode => 0750 };

	# Certs & key
	ACNE::Util::File::writeStr(join("\n", @chain), catfile($livedir, 'fullchain.pem'));
	ACNE::Util::File::writeStr(shift @chain,       catfile($livedir, 'cert.pem'));
	ACNE::Util::File::writeStr(join("\n", @chain), catfile($livedir, 'chain.pem'));
	$pkey->save(catfile($livedir, 'key.pem'), 0640);

	# Switch link
	say "Switching $id to version $sha";
	{
		no autodie qw(unlink);
		unlink $livesym_t;
		symlink $livedir_r, $livesym_t;
		rename $livesym_t, $livesym;
	}

	if ( defined $run or !$norun ) {
		# Expand hooks to full path
		my @_run = map { catfile(@ACNE::Common::etcdir, 'hooks', $_) } @$run;

		# Save all the hooks so we can run a global postinst
		$postinst{$_} = 1 for @_run;

		# Call out to hooks
		_runhooks(
			hooks   => \@_run,
			arg     => 'install',
			environ => {
				'name'          => $id,
				'fullchain'     => catfile($livesym, 'fullchain.pem'),
				'chain'         => catfile($livesym, 'chain.pem'),
				'cert'          => catfile($livesym, 'cert.pem'),
				'key'           => catfile($livesym, 'key.pem'),
				'fullchain_ver' => catfile($livedir, 'fullchain.pem'),
				'chain_ver'     => catfile($livedir, 'chain.pem'),
				'cert_ver'      => catfile($livedir, 'cert.pem'),
				'key_ver'       => catfile($livedir, 'key.pem')
			}
		);
	}

	1;
}

sub preflight {
	my ($s) = @_;
	my @dns = @{$s->{'conf'}->{'dns'}};
	my @tested_ok;

	my $tester = $s->domainAuthTestSetup;
	for my $domain ( @dns ) {
		say "Running pre-flight test for $domain";
		eval { $tester->test($domain) };
		if ( $@ ) {
			say STDERR "Pre-flight test for $domain failed: ", $@;
		}
		else {
			push @tested_ok, $domain;
		}
	}

	# FIXME For now we just die. Might want to allow to continue without the
	# problem domains if operator wants to.
	if ( @dns != @tested_ok ) {
		die "Some dns names failed the pre-flight check - aborting\n";
	}

	say "Pre-flight testing succeeded.";
	$s->{'tested'} = \@tested_ok;

	1;
}

sub order {
	my ($s, $acme) = @_;
	my $acmeroot = catdir(@{$config->{'challenge'}->{'http01fs'}->{'acmeroot'}});
	my @tested = @{$s->{'tested'}};

	if ( @tested == 0 ) {
		croak "No dns names has successfully passed pre-flight testing";
	}

	my $order = $acme->newOrder(@tested);
	say "New order ", $order->{'location'};

	# Fetch authorizations
	say "Fetching authorizations";
	my @solve;
	for my $url ( @{$order->{'authorizations'}} ) {
		my $auth = $acme->authorization($url);
		my $challenges = $auth->{'challenges'};
		my $status     = $auth->{'status'};
		my $id         = $auth->{'identifier'}->{'value'};
		
		if ( !grep { $_ eq $id } @tested ) {
			die "Identifier `$id` provided by CA do not match any dns name we requested?!";
		}

		# Already taken care of (CA might re-use authorizations)
		if ( $status eq 'valid' ) {
			say "$id authorization already valid; skipping it.";
			push @{$s->{'authorized'}}, $id;
			next;
		}

		if ( $status ne 'pending' ) {
			die "Authorization has status `$status`, not `pending` or `valid`, aborting.\n";
		}

		my @supported = grep { $_->{'type'} eq 'http-01' } @{$challenges};
		die "No supported challenges for identifier $id"
		  if @supported == 0;

		push @solve, { 'identifier' => $id, 'challenges' => \@supported };
	}

	# Write out local challenges
	for ( @solve ) {
		my $challenges = $_->{'challenges'};
		my $id         = $_->{'identifier'};

		for my $challenge ( @{$challenges} ) {
			my $token   = $challenge->{'token'};
			my $thumb   = $acme->jws->thumbprint;
			my $keyauth = $token . '.' . $thumb;
			my $path    = catfile($acmeroot, $token);
			my $url     = $challenge->{'url'};

			# Publish
			say "Publishing challenge for $id";
			ACNE::Util::File::writeStr($keyauth, $path);
			chmod 644, $path;
			$acme->challenge($url);
		}
	}

	# Poll until all have become valid
	for ( @solve ) {
		my $challenges = $_->{'challenges'};
		my $id         = $_->{'identifier'};
		for my $challenge ( @{$challenges} ) {
			my $token = $challenge->{'token'};
			my $url = $challenge->{'url'};
			my $path = catfile($acmeroot, $token);
			say "Polling for $id";
			$acme->challengePoll($url);
			unlink $path;
			push @{$s->{'authorized'}}, $id;
		}
	}

	$s->{'order'} = $order;
}

sub issue {
	my ($s, $ca) = @_;
	my $order = $s->{'order'};
	my $renew_left = $s->{'combined'}->{'renew-left'};
	my @authorized = @{$s->{'authorized'}};

	if ( @authorized == 0 ) {
		croak "No dns names was successfully authorized";
	}

	say "Making Certificate Singing Request";
	my $csr = $s->csrGenerate(@authorized);

	say "Requesting Certificate";
	my $chain = $ca->new_cert($csr, $order);

	$s->{'chain'} = $chain;

	my ($notbefore, $notafter) = ACNE::OpenSSL::Date::x509_dates(@$chain[0]);
	$s->{'notafter'} = $notafter;

	my $renewafter = $notafter - ($renew_left * 24 * 60 * 60);
	$s->{'renew'} = $renewafter;

	1;
}

# Write a random string to random filename in acmeroot
# FIXME move to challenge module along with the other http01fs stuff.
sub domainAuthTestSetup {
	my ($s) = @_;
	my $rand = ACNE::Util::Rand::craprand(20);
	my $fp = catfile(@{$config->{'challenge'}->{'http01fs'}->{'acmeroot'}}, $rand);
	ACNE::Util::File::writeStr($rand, $fp);
	chmod 644, $fp;
	bless { path => $fp, rand => $rand, http => HTTP::Tiny->new } => 'ACNE::Cert::AuthTest';
}
sub ACNE::Cert::AuthTest::test {
	my ($s, $domain) = @_;
	my $rand = $s->{'rand'};
	my $http = $s->{'http'};
	my $uri  = 'http://' . $domain . '/.well-known/acme-challenge/' . $rand;

	my $r = $http->get($uri);

	if ( $r->{'success'} ) {
		if ( $r->{'content'} ne $rand ) {
			die "Did not get the expected content\n";
		}
	}
	elsif ( $r->{'status'} == 599 ) {
		die $r->{'content'};
	}
	else {
		die "Bad HTTP status ", $r->{'status'}, " ", $r->{'reason'}, "\n";
	}
}
sub ACNE::Cert::AuthTest::DESTROY { unlink $_[0]->{'path'}; }

# FIXME most of this probably wants to go to ACNE::OpenSSL::PKCS10
sub csrGenerate {
	my ($s, @domains) = @_;
	my $dir      = $s->{'dir'};
	my $keytype  = $s->{'keytype'};
	my $keyarg   = $s->{'keyarg'};
	my $combined = $s->{'combined'};
	my $roll     = $combined->{'roll-key'};

	# If roll-key = 1, we always generate new key.
	# if 0, we load the key if we have it, otherwise generate new key.
	# FIXME force roll if parameters have changed?
	my $pkey_fp     = catfile($dir, 'new-key.pem');
	my $pkey_old_fp = catfile($dir, 'key.pem');
	my $pkey;

	# Re-use key
	if ( !$roll && -e $pkey_old_fp ) {
		if ( $keytype eq 'rsa' ) {
			$pkey = ACNE::Crypto::RSA->load($pkey_old_fp);
		}
		elsif ( $keytype eq 'ecdsa' ) {
			$pkey = ACNE::Crypto::ECDSA->load($pkey_old_fp);
		}
		else {
			die "Unsupported key type $keytype";
		}
	}
	# New key
	else {
		if ( $keytype eq 'rsa' ) {
			$pkey = ACNE::Crypto::RSA->generate_key($keyarg);
		}
		elsif ( $keytype eq 'ecdsa' ) {
			$pkey = ACNE::Crypto::ECDSA->generate_key($keyarg);
		}
		else {
			die "Unsupported key type $keytype";
		}
	}
	$s->{'pkey'} = $pkey;
	$pkey->save($pkey_fp, 0640);

	# Create a CSR config which can be reused without special arguments
	my $conf_fp = catdir($dir, 'new-csr.conf');
	open my $conf_fh, '>', $conf_fp;
	print $conf_fh '[req]', "\n",
	  'distinguished_name = req_distinguished_name', "\n",
	  'req_extensions = v3_req', "\n",
	  '[req_distinguished_name]', "\n",
	  'commonName = Common Name', "\n",
	  'commonName_max = 256', "\n",
	  'commonName_default = ', $domains[0], "\n",
	  '[ v3_req ]', "\n",
	  'basicConstraints = CA:FALSE', "\n",
	  'keyUsage = nonRepudiation, digitalSignature, keyEncipherment, keyAgreement', "\n",
	  'subjectAltName = @alt_names', "\n",
	  '[alt_names]', "\n";
	while ( my ($i, $val) = each @domains ) {
		print $conf_fh sprintf("DNS.%d = %s\n", $i + 1, $val);
	}

	undef $conf_fh;

	my ($reader, $writer);
	my $pid = open3($writer, $reader, '>&STDERR',
	  'openssl', 'req', '-new', '-outform', 'DER', '-key', $pkey_fp, '-sha256', '-config', $conf_fp, '-batch'
	);
	my $output = do { local $/; <$reader> };
	waitpid($pid, 0);
	my $exitval = $? >> 8;
	die "openssl rsa exit $exitval" if $exitval != 0;

	$output;
}

sub getId         { $_[0]->{'id'}; };
sub getCAId       { $_[0]->{'combined'}->{'ca'}; }
sub getKeyConf    { $_[0]->{'keytype'} . ':' . $_[0]->{'keyarg'}; }
sub getRollKey    { $_[0]->{'combined'}->{'roll-key'}; }
sub getRun        { $_[0]->{'combined'}->{'run'}; }
sub getDNS        { $_[0]->{'combined'}->{'dns'}; }
sub getNotAfter   { $_[0]->{'notafter'}; }
sub getRenewAfter { $_[0]->{'renew'}; }

##
## No methods below. Effectively module global subs.
##

sub _runpostinst {
	my @run = sort keys %postinst;

	_runhooks(
		hooks   => \@run,
		arg     => 'postinst',
		environ => {},
	);
}

sub _runhooks {
	my (%args) = @_;
	my $hooks    = $args{'hooks'};
	my $arg     = $args{'arg'};
	my $environ = $args{'environ'};

	while ( my ($k, $v) = each %$environ ) {
		$ENV{$k} = $v;
	}

	for my $hook ( @$hooks ) {
		say "Running hook $hook $arg";
		eval {
			system $hook, $arg;
		};
		if ( $@ ) {
			say STDERR "Problem running hook $hook $arg";
			say STDERR $@;
		}
	}

	delete $ENV{$_} for keys %$environ;
}

sub _findautorenews {
	my $certs_fp = catdir(@{$config->{'system'}->{'store'}}, 'cert');
	my @certs;
	my $now = time;

	opendir(my $dh, $certs_fp);
	while ( my $dentry = readdir $dh ) {
		next if $dentry =~ /^\./;

		my $conf_fp = catfile($certs_fp, $dentry, 'config.json');
		next if ! -e $conf_fp;

		my $renew_fp = catfile($certs_fp, $dentry, 'renewafter');
		my $renewafter = 0;
		if ( -e $renew_fp ) {
			$renewafter = int(do { local $/; open my $fh, '<', $renew_fp; <$fh> });
		}
		next if $now < $renewafter;

		push @certs, $dentry;
	}

	@certs;
}

1;
