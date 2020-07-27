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
	'termsOfService' => { validator => [\&ACNE::Validator::PRINTABLE] }
);

sub new {
	my ($class, %args) = @_;
	my $directory  = $args{'directory'} || croak "directory parameter missing";
	my $verify_tls = $args{'verify_tls'} ? 1 : 0;

	my $jws = ACME::Client::JWS->new();
	my $http = HTTP::Tiny->new('verify_SSL' => $verify_tls);

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

sub newAccount {
	my ($s, %req) = @_;
	my $http_expect_status = 201;

	if ( $req{onlyReturnExisting} ) {
		$http_expect_status = 200;
	}

	# Switch to JSON bools
	for my $key (newAccount_bools()) {
		next if !exists $req{$key};
		$req{$key} = $req{$key} ? JSON::PP::true : JSON::PP::false;
	}

	my ($account, $h) = $s->_post($s->directory('newAccount'), \%req,
	  {use_jwk => 1, expected_status => $http_expect_status});

	if ( !exists $h->{'location'} ) {
		die "ACME server did not provide a account location.";
	}

	if (wantarray) {
		return ($account, $h->{'location'});
	}

	return $account;
}

sub updateAccount {
	my ($s, %req) = @_;
	my $http_expect_status = 200;

	# Switch to JSON bools
	for my $key (newAccount_bools()) {
		next if !exists $req{$key};
		$req{$key} = $req{$key} ? JSON::PP::true : JSON::PP::false;
	}

	return scalar $s->_post($s->{'location'}, \%req,
	  {expected_status => $http_expect_status});
}

sub newOrder {
	my ($s, @domains) = @_;

	my $req = { 'identifiers' => [] };
	foreach my $domain ( @domains ) {
		push @{$req->{'identifiers'}}, {'type' => 'dns', 'value' => $domain};
	}

	my ($json, $h) = $s->_post($s->directory('newOrder'), $req, {expected_status => 201});

	$json->{'location'} = $h->{'location'}
	  or die "newOrder: missing HTTP header `location`\n";

	return $json;
}

sub authorization {
	my ($s, $url) = @_;

	state $validator = ACNE::Validator->new(
		status => {
			validator => [\&ACNE::Validator::ENUM, {
				pending     => 'pending',
				valid       => 'valid',
				invalid     => 'invalid',
				deactivated => 'deactivated',
				expired     => 'expired',
				revoked     => 'revoked'
			}]
		},
		expires => {
			default   => undef,
			validator => [\&ACNE::Validator::PRINTABLE] # FIXME MAYBE RFC3339 validator
		}
	);
	state $identifier_validator = ACNE::Validator->new(
		type  => {
			validator => [sub { die "only \"dns\" is supported\n" if $_[0] ne 'dns'; $_[0]}]
		},
		value => {
			validator => [\&ACNE::Validator::PRINTABLE]
		}
	);
	state $challenge_validator = ACNE::Validator->new(
		type => {
			validator => [\&ACNE::Validator::PRINTABLE]
		},
		url => {
			validator => [\&ACNE::Validator::PRINTABLE]
		},
		token => {
			validator => [\&ACNE::Validator::PRINTABLE]
		}
	);

	my $auth = $s->_post($url, undef); # POST-as-GET

	die "No identifier in CA response for $url!"
	  if !exists $auth->{'identifier'};

	die "No challenges in CA response for $url!"
	  if !exists $auth->{'challenges'};

	my %temp = ( 'challenges' => [] );
	$temp{'identifier'} = $identifier_validator->process(delete $auth->{'identifier'});

	for my $challenge ( @{$auth->{'challenges'}} ) {
		push @{$temp{'challenges'}}, scalar $challenge_validator->process($challenge);
	}
	delete $auth->{'challenges'};

	my $rest = $validator->process($auth);
	my %ret = (%temp, %{$rest});

	return \%ret;
}

sub challenge {
	my ($s, $url) = @_;
	$s->_post($url, {});
}

sub challengePoll {
	my ($s, $url) = @_;

	# Wait for ready
	my $status;
	for ( my $try = 0; $try < 10; $try++ ) {
		my $ch = $s->_post($url, undef); # POST-as-GET
		$status = $ch->{'status'};

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

	die "Challenge timed out!"
	  if $status ne 'valid';

	1;
}

sub finalize {
	my ($s, $order, $csr) = @_;
	my $url = $order->{'finalize'};

	# Send CSR to finilizaton url
	my $req = {
	  'csr'      => encode_base64url($csr)
	};

	$s->_post($url, $req);
}

sub certificate {
	my ($s, $order) = @_;
	my $url = $order->{'location'};

	# Wait for ready
	my $cert;
	for ( my $try = 0; $try < 10; $try++ ) {
		my $polled = $s->_post($url, undef); # POST-as-GET
		$cert = $polled->{'certificate'};

		if ( !$cert ) {
			sleep 2;
		}
		else {
			last;
		}
	}

	die "Gave up waiting for certificate!"
	  if !$cert;

	# POST-as-GET
	my $pemchain = $s->_post($cert, undef, {accept => 'application/pem-certificate-chain'});
	my @chain = _cert_split_chain($pemchain);
	\@chain;
}

sub jws       { $_[0]->{'jws'}; }
sub directory { $_[0]->{'directory'}->{$_[1]} or die "request name \"$_[1]\" not in directory"; }
sub tos       { $_[0]->{'tos'}; }
sub ct_parse  { (split(/;/, $_[0]))[0]; }

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

sub _post {
	my ($s, $url, $payload, $opts) = @_;
	my $accept          = exists $opts->{'accept'} ? $opts->{'accept'} : 'application/json';
	my $use_jwk         = $opts->{'use_jwk'} ? 1 : 0;
	my $expected_status = exists $opts->{'expected_status'} ? $opts->{'expected_status'} : 200;

	my $http = $s->{'http'};
	my $jws  = $s->{'jws'};

	my $headers = {
		'Content-Type' => 'application/jose+json',
		'Accept'       => $accept
	};

	my $nonce = $s->nonce_shift();
	my $signed = $jws->sign($payload, { url => $url, nonce => $nonce }, $use_jwk);
	my $r  = $http->post($url, { content => $signed, headers => $headers });
	my $h  = $r->{'headers'};
	my $ct = ct_parse($h->{'content-type'});

	$s->nonce_push($r);
	$s->_check_error($r);

	if ( !defined $ct ) {
		die "No Content-Type provided by server\n";
	}

	if ( $accept ne $ct ) {
		my $printable = ACNE::Validator::PRINTABLE($ct);
		die "Got Content-Type \"$printable\", not \"$accept\" as expected\n";
	}

	my $ret = $ct eq 'application/json'
	  ? decode_json($r->{'content'}) : $r->{'content'};

	if (wantarray) {
		return ($ret, $h);
	}

	return $ret;
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
		my $t = ct_parse($h->{'content-type'});

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

1;
