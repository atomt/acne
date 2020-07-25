package ACME::Client;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACNE::Validator;

use ACME::Client::JWS;
use JSON::PP;
use HTTP::Tiny;
use MIME::Base64 qw(encode_base64 encode_base64url);

use constant newAccount_bools => qw(
	termsOfServiceAgreed
	onlyReturnExisting
);

# Lock directory to HTTPS
my $https_uri = { validator => [\&ACNE::Validator::REGEX, qr!^(https://.*)$!x] };
my $httpx_uri = { validator => [\&ACNE::Validator::REGEX, qr!^(https?://.*)$!x] };
my $directory_validator = ACNE::Validator->new(
	'newNonce'    => $https_uri,
	'newOrder'    => $https_uri,
	'newAccount'  => $https_uri,
	'revokeCert'  => $https_uri,
	'keyChange'   => $https_uri
);
my $directory_meta_validator = ACNE::Validator->new(
	'termsOfService' => $httpx_uri
);

sub new {
	my ($class, %args) = @_;
	my $directory = $args{'directory'} || croak "directory parameter missing";

	my $jws = ACME::Client::JWS->new();
	my $http = HTTP::Tiny->new('verify_SSL' => 1 );

	bless {
	  'jws'           => $jws,
	  'http'          => $http,
		'location'      => undef,
	  'nonces'        => [],     # replay-detection
	  'directory'     => undef,  # links loaded from /directory
		'tos'           => undef,
		'directory_url' => $directory
	} => $class;
}

sub pkey_set {
	my ($s, $pkey) = @_;
	my $jws = $s->{'jws'};
	$jws->pkey_set($pkey);
}

sub kid_set {
	my ($s, $kid) = @_;
	my $jws = $s->{'jws'};
	$jws->kid_set($kid);
	$s->{'location'} = $kid;
}

sub initialize {
	my ($s) = @_;
	my $http      = $s->{'http'};
	my $directory = $s->{'directory_url'};
	my $options = {
		headers => { 'Accept' => 'application/json' }
	};

	if ( defined $s->{'directory'} ) {
		return 1;
	} 

	# Load directory, containing uris for each supported api request
	my $r = $http->get($directory, $options);
	$s->nonce_push($r);

	my $directory_raw = decode_json($r->{'content'});
	if ( !exists $directory_raw->{'newOrder'} ) {
		die "Failed to detect presence of ACMEv2 support in CA directory\n";
	}

	$s->{'directory'} = $directory_validator->process($directory_raw);
	my $meta = $directory_meta_validator->process($directory_raw->{'meta'});
	$s->{'tos'} = $meta->{'termsOfService'};

	1;
}

sub jws       { $_[0]->{'jws'}; }
sub directory { $_[0]->{'directory'}->{$_[1]} or die "request name \"$_[1]\" not in directory"; }
sub tos       { $_[0]->{'tos'}; }

sub _post {
	my ($s, $url, $payload, $use_jwk, $accept) = @_;
	my $http = $s->{'http'};
	my $jws  = $s->{'jws'};

	$accept = 'application/json' if !defined $accept;

	my $headers = {
		'Content-Type' => 'application/jose+json',
		'Accept'       => $accept
	};

	my $nonce = $s->nonce_shift();
	my $signed = $jws->sign($payload, { url => $url, nonce => $nonce }, $use_jwk);
	my $r  = $http->post($url, { content => $signed, headers => $headers });
	my $h  = $r->{'headers'};
	my $ct = $h->{'content-type'};

	$s->nonce_push($r);
	$s->_check_error($r);

	if ( !defined $ct ) {
		die "No Content-Type provided by server\n";
	}

	if ( $accept ne $ct ) {
		my $printable = ACNE::Validator::PRINTABLE($ct);
		die "Got Content-Type \"$printable\", not \"$accept\" as expected\n";
	}

	$r;
}

sub newAccount {
	my ($s, %req) = @_;
	my $http_expect_status = 201;

	# Searching uses JWK
	if ( $req{onlyReturnExisting} ) {
		$http_expect_status = 200;
	}

	# Switch to JSON bools
	for my $key (newAccount_bools()) {
		next if !exists $req{$key};
		$req{$key} = $req{$key} ? JSON::PP::true : JSON::PP::false;
	}

	my $r = $s->_post($s->directory('newAccount'), \%req, 1);
	my $h      = $r->{'headers'};
	my $status = $r->{'status'};

	if ( $status != $http_expect_status ) {
		die "ACME server returned unexpected HTTP status $status, expected $http_expect_status";
	}

	if ( !exists $h->{'location'} ) {
		die "ACME server did not provide a account location.";
	}

	return $h->{'location'};
}

sub updateAccount {
	my ($s, %req) = @_;
	my $http_expect_status = 200;

	# Switch to JSON bools
	for my $key (newAccount_bools()) {
		next if !exists $req{$key};
		$req{$key} = $req{$key} ? JSON::PP::true : JSON::PP::false;
	}
	my $r = $s->_post($s->{'location'}, \%req, 0);
	my $h      = $r->{'headers'};
	my $status = $r->{'status'};

	if ( $status != $http_expect_status ) {
		die "ACME server returned unexpected HTTP status $status, expected $http_expect_status";
	}

	1;
}

sub newOrder {
	my ($s, @domains) = @_;

	state $identifier_validator = ACNE::Validator->new(
		type  => {
			validator => [sub { die "only \"dns\" is supported\n" if $_[0] ne 'dns'}]
		},
		value => {
			validator => [\&ACNE::Validator::PRINTABLE]
		}
	);
	state $validator = ACNE::Validator->new(
		status => {
			default   => 'pending',
			validator => [\&ACNE::Validator::ENUM, {
				unknown    => 'unknown',
				pending    => 'pending',
				processing => 'processing',
				valid      => 'valid',
				invalid    => 'invalid',
				revoked    => 'revoked'
			}]
		},
		expires => {
			default   => undef,
			validator => [\&ACNE::Validator::PRINTABLE] # FIXME MAYBE RFC3339 validator
		}
	);

	my $req = {};
	my @identifiers;
	foreach my $domain ( @domains ) {
		push @identifiers, {'type' => 'dns', 'value' => $domain};
	}
	$req->{'identifiers'} = \@identifiers;

	my $r = $s->_post($s->directory('newOrder'), $req);
	my $status = $r->{'status'};
	my $h      = $r->{'headers'};

	if ( $status != 201 ) {
		die "Error requesting challenge: $status $r->{reason}\n";
	}

	my $json = decode_json($r->{'content'});

	my $location = $h->{'location'};
	my $authorizations = delete $json->{'authorizations'};
	my $finalize = delete $json->{'finalize'};
	my @challenges;
	for my $authorization ( @$authorizations ) {
		my $r = $s->_post($authorization, undef); # post-as-get
		my $status = $r->{'status'};
		if ( $status != 200 ) {
			die "Error requesting authorization: $status $r->{reason}\n";
		}

		# contains the challenges
		my $json = decode_json($r->{'content'});
		my $identifier = $identifier_validator->process(delete $json->{'identifier'});

		# The challenges server supports for this dns name.
		# Validation of challenge is left to the code handling challenges.
		my $_challenges = delete $json->{'challenges'}
		  or die "No challenges in json from server\n";

		if ( ref $_challenges ne 'ARRAY' ) {
			die "challenges in json from server not a list\n";
		}

		push @challenges, @$_challenges;

		# We should be left with: status (default pending), expires (RFC3339, optional)
		# XXX filter challenges that are already status = 'valid'
		my $rest = $validator->process($json);
		my $astatus = $rest->{'status'};

		if ( $astatus ne 'pending' and $astatus ne 'valid' ) {
  		die "status of authorization is not pending or valid\n";
		}
	}

	{
		'finalize'   => $finalize,
		'challenges' => \@challenges,
		'location'   => $location
	};
}

sub challenge {
	my ($s, $url, $auth) = @_;
	my $req = { 'resource' => 'challenge', 'keyAuthorization' => $auth };

	my $r = $s->_post($url, $req);
	if ( $r->{'status'} != 200 ) {
		die "Error triggering challenge: $r->{status} $r->{reason}\n";
	}

	# Wait for ready
	while ( 1 ) {
		my $status = $s->challengePoll($url);
		if ( $status eq 'pending' ) {
			sleep 2;
		}
		elsif ( $status eq 'valid' ) {
			last;
		}
		else {
			die "Challenge did not pass!\n";
		}
	}

	1;
}

sub challengePoll {
	my ($s, $url) = @_;

	my $r = $s->_post($url, undef); # POST-as-GET
	my $status = $r->{'status'};
	my $h      = $r->{'headers'};
	my $ct     = $h->{'content-type'};

	if ( $status != 200 ) {
		die "Error polling challenge: $status $r->{reason}\n";
	}

	my $json = decode_json($r->{'content'});
	$json->{'status'};
}

sub new_cert {
	my ($s, $csr, $order) = @_;
	my $finalize_url = $order->{'finalize'};
	my $order_url = $order->{'location'};

	# Send CSR to finilizaton url
	my $req = {
	  'csr'      => encode_base64url($csr)
	};

	my $r = $s->_post($finalize_url, $req);

	if ( $r->{'status'} != 200 ) {
		die "Error signing certificate: $r->{status} $r->{reason}\n";
	}

	# Poll the order url to see if there is a certificate to fetch
	$r = $s->_post($order_url, undef); # POST-as-GET
	if ( $r->{'status'} != 200 ) {
		die "Error polling order status: $r->{status} $r->{reason}\n";
	}

	my $order_polled = decode_json($r->{'content'});
	my $cert_url = $order_polled->{'certificate'};
	if ( !$cert_url ) {
		die "No certificate!";
	}

	# POST-as-GET
	$r = $s->_post($cert_url, undef, 0, 'application/pem-certificate-chain');

	if ( $r->{'status'} != 200 ) {
		die "Error getting certificate: $r->{status} $r->{reason}\n";
	}

	my @chain = _cert_split_chain($r->{'content'});
	\@chain;
}

sub nonce_push {
	my ($s, $req) = @_;
	my $hdr = $req->{'headers'};
	my $nonce = $hdr->{'replay-nonce'};

	if ( !defined $nonce ) {
		return;
	}

	push @{$s->{'nonces'}}, $nonce;
	1;
}

sub nonce_shift {
	my ($s) = @_;
	my $nonces = $s->{nonces};
	my $nonce = shift @{$nonces};

	if ( defined $nonce ) {
		return $nonce;
	}

	# gotta fetch some, then.
	my $http = $s->{'http'};
	my $url = $s->directory('newNonce');
	my $req = $http->head($url);
	if ( !$req->{'success'} ) {
		die "failed to get nonce from $url";
	}
	$s->nonce_push($req);
	$s->nonce_shift;
}

sub _check_error {
	my ($s, $r) = @_;
	my $api = $s->{'api'};

	# Stuff we output to terminal, so be careful.
	state $error_validator = ACNE::Validator->new(
		'type'        => { validator => [\&ACNE::Validator::REGEX, qr/^urn:ietf:params:acme:error:(\w+)$/x] },
		'detail'      => { validator => [\&ACNE::Validator::PRINTABLE] }
	);

	if ( !$r->{'success'} ) {
		my $h = $r->{'headers'};
		my $t = $h->{'content-type'};

		if ( defined $t && $t eq 'application/problem+json' ) {
			my ($data, $err) = $error_validator->process(decode_json($r->{'content'}));
			if ( defined $err ) {
				die "Authority returned an error but the error is bogus!\n", @$err;
			}
			die 'ACME host returned error: ', $data->{'detail'}, ' (', $data->{'type'}, ")\n";
		}

		die 'ACME host returned HTTP error: ', $r->{'status'}, ' ', $r->{'reason'}, "\n";
	}

	1;
}

sub _cert_split_chain {
	my ($pem) = @_;
	my @chain;
	my $re = qr/(-----BEGIN CERTIFICATE-----\s[a-zA-Z0-9\s\+\=\/]*-----END CERTIFICATE-----)/;

	while ( $pem =~ /$re/gs ) {
		push @chain, $1;
	}

	return @chain;
}

## XXX needs updating and use in new_cert
sub _cert_get {
	my ($s, $uri) = @_;
	my $http = $s->{'http'};

	my $r = $http->get($uri);

	if ( $r->{'status'} != 200 ) {
		$s->_check_error($r);
		die "_cert_get $r->{status} $r->{reason}";
	}

	my $links = _links($r->{'headers'});
	my $next  = $links->{'up'};

	return ($r->{'content'}, $next);
}

sub _links {
	my ($headers) = @_;
	my $ret = {};

	my $links = $headers->{'link'}
	  or return $ret;

	my $http_link_re = qr/^\<(.*)\>;rel=\"(.*)\"$/;

	for my $entry ( ref $links eq 'ARRAY' ? @$links : $links ) {
		if ( my ($uri, $rel) = $entry =~ $http_link_re ) {
			$ret->{$rel} = $uri;
			#say $link, ' ', $rel;
		}
		else {
			die "bullshit link header \"$entry\"\n";
		}
	}
	$ret;
}

1;
