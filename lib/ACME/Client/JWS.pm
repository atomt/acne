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
	my ($class) = @_;

	bless {
	  'pkey'   => undef,
		'jwk'    => undef,
		'kid'    => undef,
		'alg'    => 'RS256'
	} => $class;
}

sub pkey_set {
	my ($s, $pkey) = @_;

	# the jwk header is used if we dont have a kid
	my $kparams = _key2hash($pkey);
	my $jwk = {
			'kty' => 'RSA',
			'e'   => encode_base64url($kparams->{e}), # pub exponent
			'n'   => encode_base64url($kparams->{n})  # pub key
	};

	$s->{'jwk'} = $jwk;
	$s->{'pkey'} = $pkey;
}

sub kid_set {
	my ($s, $kid) = @_;
	$s->{'kid'} = $kid;
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
	my ($s, $payload, $add_to_protected, $use_jwk) = @_;
	my $alg  = $s->{'alg'};
	my $jwk  = $s->{'jwk'};
	my $kid  = $s->{'kid'};
	my $pkey = $s->{'pkey'};

	my $header = {'alg' => $alg };
	if ( $use_jwk ) {
		$header->{'jwk'} = $jwk;
	}
	else {
		$header->{'kid'} = $kid;
	}

	my $payload64 = encode_base64url($payload);
	my $header_clone = _clone($header);
	my %protected = (%$header_clone, %$add_to_protected);
	my $protected64 = encode_base64url(encode_json(\%protected));

	$pkey->use_sha256_hash;
	my $signature = $pkey->sign($protected64 . '.' . $payload64);

	my $packet = {
		'protected' => $protected64,
		'payload'   => $payload64,
		'signature' => encode_base64url($signature)
	};

	encode_json($packet);
}

sub thumbprint {
	my ($s) = @_;
	my $jwk = $s->{'jwk'};
	encode_base64url(sha256(JSON::PP->new->canonical(1)->encode($jwk)));
}

1;
