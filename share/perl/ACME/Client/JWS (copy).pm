package ACME::Client::JWS;
#
# A very basic JWS client implementation.
#
# Only tested with ACME. It handles nonces internally which makes it
# unlikely to work with non-ACME endpoints. And for now RSA/SHA256 only.
#
# pkey in constructor expects a Crypt::OpenSSL::RSA object.
#
use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use JSON;
use MIME::Base64 qw(encode_base64url);
use Digest::SHA qw(sha256_base64);
use Data::Dumper; # Used instead of Clone because it's in core.
use HTTP::Tiny;

sub new {
	my ($class, %args) = @_;
	my $baseurl = $args{'baseurl'} || croak "No url parameter";
	my $pkey    = $args{'pkey'}    || croak "No pkey parameter";

	my $kparams = _key2hash($pkey);
	my $header = {
		'alg' => 'RS256',
		'jwk' => {
			'kty' => 'RSA',
			'e'   => encode_base64url($kparams->{e}), # pub exponent
			'n'   => encode_base64url($kparams->{n})  # pub key
		}
	};

	my $http = HTTP::Tiny->new(
	  'verify_SSL'      => 1,
	  'default_headers' => {
	    'Accept'       => 'application/json',
	    'Content-Type' => 'application/json'
  	  }
  	);

	# Get initial nonce (will also flag if url is incorrect)
	my $nonce = _getNonceOnly($http, $baseurl . '/directory');

	bless {
	  'pkey'       => $pkey,
	  'header'     => $header,
	  'nonce'      => $nonce,
	  'baseurl'    => $baseurl,
	  'http'       => $http
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

# Request initial nonce (needed?)
sub _getNonceOnly {
	my ($http, $url) = @_;

	my $resp = $http->head($url);
	my $status  = $resp->{'status'};
	my $reason  = $resp->{'reason'};
	my $headers = $resp->{'headers'};

	if ( $status != 200 ) {
		die "HEAD $url failed: $status\n";
	}

	if ( my $nonce = $headers->{'replay-nonce'} ) {
		return $nonce;
	}

	die "No nonce could be aquired! $status $reason\n";
}

sub sign {
	my ($s, $payload) = @_;
	my $header = $s->{'header'};
	my $pkey   = $s->{'pkey'};
	my $nonce  = $s->{'nonce'};

	my $payload64 = encode_base64url(encode_json($payload));
	my $protected = eval Dumper($header); # clone
	$protected->{'nonce'} = $nonce;

	$pkey->use_sha256_hash;
	my $protected64 = encode_base64url(encode_json($protected));
	my $signature = $pkey->sign($protected64 . '.' . $payload64);

	my $packet = {
		'header'    => $header,
		'protected' => $protected64,
		'payload'   => $payload64,
		'signature' => encode_base64url($signature)
	};

	$packet;
}

sub post {
	my ($s, $url, $request) = @_;
	my $http    = $s->{'http'};
	my $baseurl = $s->{'baseurl'};
	my $fullurl = $baseurl . $url;

	my $signed  = $s->sign($request);
	my $resp    = $http->post($baseurl . $url, { content => encode_json($signed) });
	my $status  = $resp->{'status'};
	my $reason  = $resp->{'reason'};
	my $headers = $resp->{'headers'};

	if ( my $nonce = $headers->{'replay-nonce'} ) {
		$s->{'nonce'} = $nonce;
	}
	else {
		say $resp->{'content'};
		die "No nonce could be aquired! $status $reason\n";
	}

	return ($status, $reason, decode_json($resp->{'content'}));
}


sub thumbprint {
	my ($s) = @_;
	my $jwk = $s->{'header'}->{'jwk'};
	sha256_base64(JSON->new->canonical(1)->encode($jwk));
}

1;