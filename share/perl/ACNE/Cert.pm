package ACNE::Cert;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::Common;
use ACNE::Util::File;
use ACNE::Crypto::RSA;

use HTTP::Tiny;
use File::Spec::Functions;
use IPC::Open3;

sub _new {
	my ($class, $id, $conf) = @_;

	# Load defaults and ca config early to get early feedback.
	my $defaults = ACNE::Util::File::readPairs(catfile(@ACNE::Common::etcdir, 'defaults'));
	$defaults->{for} = [$defaults->{for}]; # FIXME
	my $combined; { my %tmp = (%$defaults, %$conf); $combined = \%tmp };
	
	# Make sure CA, account and for is always saved to the cert json
	# regardless if specified on command line.
	$conf->{ca}      = $combined->{ca};
	$conf->{account} = $combined->{account};
	$conf->{for}     = $combined->{for};

	bless {
	  id       => $id,
	  dir      => catdir(@ACNE::Common::libdir, 'cert', $id),
	  conf     => $conf,
	  defaults => $defaults,
	  combined => $combined
	} => $class;
}

# Create new object
sub new {
	my ($class, $id, $conf) = @_;

	# Clean config (removes options not specified)
	while ( my($key, $val) = each %$conf ) {
		delete $conf->{$key} if !defined $val;
	}
	delete $conf->{'for'} if @{$conf->{'for'}} == 0;

	my $s = _new(@_);
	my $dir = $s->{'dir'};

	if ( ! -e $dir ) {
		mkdir $dir, 0700;
	}

	die "certificate ID \"$id\" already exists\n"
	  if -d catfile($dir, 'cert');

	$s;
}

# Load config from db and return new object
# FIXME allow for setting new key, for and renew parameters
sub load {
	my ($class, $id) = @_;
	my $conf_fp = catfile(@ACNE::Common::libdir, 'cert', $id, 'config.json');
	_new(@_, ACNE::Util::File::readJSON($conf_fp));
}

# Write cert files to cert db
sub save {
	my ($s) = @_;
	my $id  = $s->{'id'};
	my $dir = $s->{'dir'};

	my $conf_fp = catfile(@ACNE::Common::libdir, 'cert', $id, 'config.json');

	if ( ! -e $dir ) {
		mkdir $dir, 0700;
	}

	ACNE::Util::File::writeJSON($s->{'conf'}, $conf_fp);
}

sub issue {
	my ($s, $ca) = @_;
	my @dns = @{$s->{'conf'}->{'dns'}};

	# Authorize domains
	for my $domain ( @dns ) {
		say "Authenticating domain $domain";
		$s->domainAuth($ca, $domain)
	}

	# Make CSR and request the cert(s)
	say "Making Certificate Singing Request";
	my $csr = $s->csrGenerate;

	say "Requesting Certificate";
	say $ca->new_cert($csr);
}

sub domainAuth {
	my ($s, $acme, $domain) = @_;

	# Perhaps have a challenge hook like the install.d/remove.d ones
	# -> we could use dns challenges and such as well.
	my $acme_dir = '/srv/web/shared/acme'; # FIXME read from config

	say "Requesting challenges";
	my @challenges_all = $acme->new_authz($domain);
	my @challenges = grep { $_->{'type'} eq 'http-01' } @challenges_all;

	if ( @challenges == 0 ) {
		die "No supported challenges provided by CA\n";
	}

	my $challenge = $challenges[0];

	# Make challenge file
	my $token     = $challenge->{'token'};
	my $thumb     = $acme->jws->thumbprint;
	my $keyauth   = $token . '.' . $thumb;
	my $path      = catfile($acme_dir, $token);

	say "Got challenge from CA, publishing";
	open my $fh, '>', $path;
	print $fh $keyauth;
	undef $fh;
	chmod 644, $path;

	# Do a sanity test, see if we can fetch the challenge ourselfes
	# before we request the CA to go get it.
	my $url = 'http://' . $domain . '/.well-known/acme-challenge/' . $token;
	say "Testing $url";
	my $resp = HTTP::Tiny->new->get($url);

	if ( $resp->{'content'} ne $keyauth ) {
		die "Content of the token on the server did not match the one we put there..!\nGot $resp->{content}";
	}

	# Notify CA to go fetch
	say "Notifying CA that we are ready";
	$acme->challenge($challenge->{'uri'}, $keyauth);
	say "Domain $domain verified!";

	unlink $path;

	1;
}

# FIXME most of this probably wants to go to ACNE::OpenSSL::PKCS10
sub csrGenerate {
	my ($s) = @_;
	my $dir      = $s->{'dir'};
	my $combined = $s->{'combined'};
	my @dns      = @{$combined->{'dns'}};
	my $key      = $combined->{'key'};
	my $roll     = $combined->{'roll-key'};
	
	# If roll-key = 1, we always generate new key.
	# if 0, we load the key if we have it, otherwise generate new key.
	# FIXME not EC aware
	# FIXME force roll if parameters have changed?
	my $pkey_fp     = catfile($dir, 'new-key.pem');
	my $pkey_old_fp = catfile($dir, 'key.pem');
	my $pkey;

	if ( !$roll && -e $pkey_old_fp ) {
		$pkey = ACNE::Crypto::RSA->load($pkey_old_fp);
	}
	else {
		$pkey = $s->pkeyCreate($key);
	}
	$pkey->save($pkey_fp, 0600);

	# Create a CSR config which can be reused without special arguments
	my $conf_fp = catdir($dir, 'new-csr.conf');
	open my $conf_fh, '>', $conf_fp;
	print $conf_fh '[req]', "\n",
	  'distinguished_name = req_distinguished_name', "\n",
	  'req_extensions = v3_req', "\n",
	  '[req_distinguished_name]', "\n",
	  'commonName = Common Name', "\n",
	  'commonName_max = 256', "\n",
	  'commonName_default = ', $dns[0], "\n",
	  '[ v3_req ]', "\n",
	  'basicConstraints = CA:FALSE', "\n",
	  'keyUsage = nonRepudiation, digitalSignature, keyEncipherment, keyAgreement', "\n";

	if ( @dns > 1 ) {
		print $conf_fh
		  'subjectAltName = @alt_names', "\n",
		  '[alt_names]', "\n";
		while ( my ($i, $val) = each @dns ) {
			print $conf_fh sprintf("DNS.%d = %s\n", $i + 1, $val);
		}
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

sub getId        { $_[0]->{'id'}; };
sub getCAId      { $_[0]->{'combined'}->{'ca'}; }
sub getAccountId { $_[0]->{'combined'}->{'account'}; }
sub getKeyConf   { $_[0]->{'combined'}->{'key'}; }
sub getRollKey   { $_[0]->{'combined'}->{'roll-key'}; }

sub pkeyCreate {
	my ($s, $conf) = @_;
	my $ret;

	my ($type, $arg) = split(/:/, $conf, 2);
	if ( $type eq 'rsa' ) {
		$ret = ACNE::Crypto::RSA->generate_key($arg);
	}
	else {
		die "Unsupported key type \"$type\"\n";
	}

	$ret;
}

1;