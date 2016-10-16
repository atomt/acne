package ACNE::OpenSSL::ECDSA;
#
# Crypt::OpenSSL::ECDSA compatibleish openssl binary wrapper.
# Complete enough for loading/creating keys only.
#
use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

#use ACNE::OpenSSL::RSA::FakeNum;
use IPC::Open3;

sub generate_key {
	my ($class, $arg_curve) = @_;

	my ($writer, $reader);
	open my $null, '>', '/dev/null';
	#openssl ecparam -out ec_client_key.pem -name secp384r1 -genkey
	my $pid = open3($writer, $reader, $null, 'openssl', 'ecparam', '-name', $arg_curve, '-genkey');
	my $pem = do { local $/; <$reader> };
	waitpid($pid, 0);
	my $exitval = $? >> 8;
	die "openssl genrsa exit $exitval" if $exitval != 0;

	my $curve = _parseKey($pem);

	bless {
		hasharg => '-md5',
		curve   => $curve,
		pem     => $pem
	} => $class;
}

sub new_private_key {
	my ($class, $pem) = @_;

	my $curve = _parseKey($pem);

	bless {
		hasharg => '-md5',
		curve   => $curve,
		pem     => $pem
	} => $class;
}

# ASN1 OID: secp384r1
# NIST CURVE: P-384
my $key_re = qr/^
	ASN1\ OID:\ (?<oid>\w+)
/x;

sub _parseKey {
	my ($pem) = @_;

	# Pass the pem through openssl for decoding, without writing to fs
	my ($writer, $reader);
	my $pid = open3($writer, $reader, '>&STDERR', 'openssl', 'ecparam', '-noout', '-text');
	print $writer $pem;
	my $output = do { local $/; <$reader> };

	waitpid($pid, 0);
	my $exitval = $? >> 8;
	die "openssl ecparam exit $exitval" if $exitval != 0;

	my @parsed = $output =~ $key_re
	  or die "we did not understand openssls ecparam output\n$output";

	shift @parsed;
}

sub import_random_seed     { 1; }
sub get_private_key_string { $_[0]->{'pem'}; }
sub get_key_parameters     { @{$_[0]->{'params'}}; }
sub use_md5_hash           { $_[0]->{'hasharg'} = '-md5'; }
sub use_sha1_hash          { $_[0]->{'hasharg'} = '-sha1'; }
sub use_sha224_hash        { $_[0]->{'hasharg'} = '-sha224'; }
sub use_sha256_hash        { $_[0]->{'hasharg'} = '-sha256'; }
sub use_sha512_hash        { $_[0]->{'hasharg'} = '-sha512'; }

1;
