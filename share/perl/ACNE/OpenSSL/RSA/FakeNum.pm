package ACNE::OpenSSL::RSA::FakeNum;
#
# Crypt::OpenSSL::Bignum lookalike for storing key data.
#
use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

sub new {
	my ($class, $data) = @_;
	bless \$data => $class;
}

sub to_hex { use bytes; uc(unpack('H*', ${$_[0]})); }
sub to_bin { ${$_[0]}; }

1;