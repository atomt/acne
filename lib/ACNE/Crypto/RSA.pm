package ACNE::Crypto::RSA;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use parent qw(ACNE::OpenSSL::RSA);
use IO::File;

sub load {
	my ($class, $path) = @_;
	open my $fh, '<', $path;
	my $pem = do { local $/; <$fh> };
    $class->SUPER::new_private_key($pem);
}

sub save {
	my ($s, $path, $perms) = @_;
	my $rsa = $s->{'rsa'};

	my $fh = IO::File->new($path, 'w', $perms)
	  or die "$path: $!\n";
	print $fh $s->SUPER::get_private_key_string;

	chmod $perms, $path
	  if defined $perms;
}

1;