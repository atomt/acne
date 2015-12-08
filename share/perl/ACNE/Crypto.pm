package ACNE::Crypto;

use 5.014;
use warnings;

use Net::SSLeay;
use ACNE::Crypto::RSA;

# getrandom/getentropy would be better.. but beats urandom as it can
# provide bad randomness for an unknown amount of time after boot.
$Net::SSLeay::random_device = '/dev/random';

sub init {
	say "Initializing crypto..";

	Net::SSLeay::load_error_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::ENGINE_load_builtin_engines();
	Net::SSLeay::ENGINE_register_all_complete();
	Net::SSLeay::randomize();

	say "Crypto intialization complete";
}

sub createPkey {
	my ($conf) = @_;
	my $ret;

	my ($type, $arg) = split(/:/, $conf, 2);
	if ( $type eq 'rsa' ) {
		$ret = ACNE::Crypto::RSA->new($arg);
	}
	else {
		die "Unsupported key type \"$type\"\n";
	}

	$ret;
}

1;