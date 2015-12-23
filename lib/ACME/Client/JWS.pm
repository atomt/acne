package ACME::Client::JWS;
#
# A very basic JWS client implementation.
#
# Only tested with ACME. For now RSA/SHA256 only.
#
# constructor expects a Crypt::OpenSSL::RSA object as pkey.
#
use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use JSON::PP;
use MIME::Base64 qw(encode_base64url);
use Digest::SHA qw(sha256);
use Data::Dumper;

sub new {
	my ($class, %args) = @_;
	my $pkey = $args{'pkey'} || croak "No pkey parameter";

	my $kparams = _key2hash($pkey);
	my $header = {
		'alg' => 'RS256',
		'jwk' => {
			'kty' => 'RSA',
			'e'   => encode_base64url($kparams->{e}), # pub exponent
			'n'   => encode_base64url($kparams->{n})  # pub key
		}
	};

	bless {
	  'pkey'   => $pkey,
	  'header' => $header
	} => $class;
}

sub _key2hash {
	my ($rsa) = @_;
	my $ret = {};

	my @params = $rsa->get_key_parameters();
	for my $name ( qw(n e d p q dp dq qi) ) {
		$ret->{$name} = shift(@params)->to_bin;
	}

	return $ret;
}

# XXX find better in-core alternative to Data::Dumper for this.
sub _clone {
	my ($in) = @_;
	my $d = Data::Dumper->new([$in]);
	$d->Purity(1)->Terse(1)->Deepcopy(1);
	eval $d->Dump;
}

sub sign {
	my ($s, $payload, $add_to_protected) = @_;
	my $header = $s->{'header'};
	my $pkey   = $s->{'pkey'};

	my $payload64 = encode_base64url(encode_json($payload));
	my $header_clone = _clone($header);
	my %protected = (%$header_clone, %$add_to_protected);
	my $protected64 = encode_base64url(encode_json(\%protected));

	$pkey->use_sha256_hash;
	my $signature = $pkey->sign($protected64 . '.' . $payload64);

	my $packet = {
		'header'    => $header,
		'protected' => $protected64,
		'payload'   => $payload64,
		'signature' => encode_base64url($signature)
	};

	encode_json($packet);
}

sub thumbprint {
	my ($s) = @_;
	my $jwk = $s->{'header'}->{'jwk'};
	encode_base64url(sha256(JSON->new->canonical(1)->encode($jwk)));
}

1;
