package ACNE::OpenSSL::RSA;
#
# Crypt::OpenSSL::RSA compatibleish openssl binary wrapper.
# Complete enough for loading/creating keys and signing.
#
use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::OpenSSL::RSA::FakeNum;
use IPC::Open3;

sub generate_key {
	my ($class, $arg_bits) = @_;

	open my $fh, '-|', 'openssl', 'genrsa', $arg_bits;
	my $pem = do { local $/; <$fh> };

	my ($bits, $params) = _parseKey($pem);

	bless {
		hasharg => '-md5',
		bits    => $bits,
		pem     => $pem,
		params  => $params
	} => $class;
}

sub new_private_key {
	my ($class, $pem) = @_;

	my ($bits, $params) = _parseKey($pem);

	bless {
		hasharg => '-md5',
		bits    => $bits,
		pem     => $pem,
		params  => $params
	} => $class;	
}

# n e d p q dp dq qi
# n = modulus / Publickey
# e = publicExponent
# d = privateExponent
# p = prime1
# q = prime2
# dp = exponent1
# dq = exponent2
# qi = coefficient
my $key_re = qr/^
	Private-Key:\ \((?<bits>[0-9]+)\ bit\)\n
	modulus:\n\s+(?<n>[a-f0-9\:\s]+?)\n
	publicExponent:\ [0-9]+\ \(0x(?<e>[a-f0-9]+)\)\n
	privateExponent:\n\s+(?<d>[a-f0-9\:\s]+?)\n
	prime1:\n\s+(?<p>[a-f0-9\:\s]+?)\n
	prime2:\n\s+(?<q>[a-f0-9\:\s]+?)\n
	exponent1:\n\s+(?<dp>[a-f0-9\:\s]+?)\n
	exponent2:\n\s+(?<dq>[a-f0-9\:\s]+?)\n
	coefficient:\n\s+(?<qi>[a-f0-9\:\s]+?)$
/x;

sub _parseKey {
	my ($pem) = @_;

	# Pass the pem through openssl for decoding, without writing to fs
	my ($writer, $reader);
	my $pid = open3($writer, $reader, '>&STDERR', 'openssl', 'rsa', '-noout', '-text');
	print $writer $pem;
	my $output = do { local $/; <$reader> };

	waitpid($pid, 0);
	my $exitval = $? >> 8;
	die "openssl rsa exit $exitval" if $exitval != 0;

	my @parsed = $output =~ $key_re
	  or die "we did not understand openssls rsa output\n";

	my $bits = shift @parsed;
	# Ok a little clunky (instead of counting + for loop iteration)
	while (my ($index, $val) = each @parsed ) {
		if ( $index == 1 ) {
			$val = ACNE::OpenSSL::RSA::FakeNum->new(pack('h*', $val));
		}
		else {
			$val =~ s![\n\s+:]+!!g;
			# usually padded, but sometimes not. Does not seem to be the
			# case with actual openssl library APIs so this looks like
			# something "openssl rsa -text" helpfully adds for us.
			$val =~ s!^00!!;
			$val = ACNE::OpenSSL::RSA::FakeNum->new(pack('H*', $val));
		}
		$parsed[$index] = $val;
	}

	return ($bits, \@parsed);
}

sub sign {
	my ($s, $payload) = @_;
	my $hasharg = $s->{'hasharg'};
	my $pem     = $s->{'pem'};

	# As we need to pass on key as well, use a extra pipe and do the
	# necessary file descriptor gymnastics with manual exec.
	#
	# We avoid deadlocking due to lack of an actual event loop bacause
	# ordering is known.

	my ($writer, $reader, $key_reader, $key_writer);
	# $^F to sneak past exec
	{ local $^F = 1024; pipe ($key_reader, $key_writer); }

	my $pid = open3($writer, $reader, '>&STDERR', '-');
	if (!defined $pid) {
		die "fork failed: $!";
	}

	if ( $pid == 0 ) {
		close $key_writer;
		exec('openssl', 'dgst', $hasharg, '-sign', '/dev/fd/' . fileno($key_reader));
		exit(1);
	}
	close $key_reader;

	# Send key
	print $key_writer $pem;
	close $key_writer;

	# Send payload
	print $writer $payload;
	close $writer;

	# Get signed
	my $ret = do { local $/; <$reader> };

	waitpid $pid, 0;
	die "OpenSSL failed signing data\n" if $? >> 8 != 0;

	$ret;
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