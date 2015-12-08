package ACNE::Crypto::RSA;

use 5.014;
use warnings;
use autodie;

use Net::SSLeay;

sub new {
	my ($class, $bits) = @_;

	if ( !Net::SSLeay::RAND_status() ) {
		die "PRNG insufficiently seeded. Have ACNE::Crypto::init been run?\n";
	}

	my $rsa = Net::SSLeay::RSA_generate_key($bits, 65537);
	my $pkey = Net::SSLeay::EVP_PKEY_new();
	Net::SSLeay::EVP_PKEY_assign_RSA($pkey, $rsa);

	bless { rsa => $rsa, pkey => $pkey } => $class;
}

sub load {
	my ($class, $path) = @_;

	my $bio = Net::SSLeay::BIO_new_file($path, 'r');
	my $pkey = Net::SSLeay::PEM_read_bio_PrivateKey($bio, undef, '');
	Net::SSLeay::BIO_free($bio);

    bless { rsa => undef, pkey => $pkey } => $class;
}

sub save {
	my ($s, $path, $perms) = @_;
	my $fh = IO::File->new($path, 'w', $perms)
	  or die "$path: $!\n";
	print $fh Net::SSLeay::PEM_get_string_PrivateKey($s->{'pkey'});
	chmod $perms, $path
	  if defined $perms;
}

sub sign {
	my ($key, $payload) = @_;
}

sub DESTROY {
	my ($s) = @_;

	my $rsa  = delete $s->{rsa};
	my $pkey = delete $s->{pkey};

#	Net::SSLeay::EVP_PKEY_free($pkey) if defined $pkey;
	Net::SSLeay::RSA_free($rsa) if defined $rsa;
	

	1;
}

1;