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

my $HTTP_RETRY_AFTER_MAX = 30;

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
	my $h = $r->{'headers'};
	my $ct = ct_parse($h->{'content-type'});

	if ( !defined $ct ) {
		die "No Content-Type provided by server\n";
	}

	if ( $ct ne 'application/json' ) {
		die "The ACME directory has incorrect content-type\n";
	}

	if ( !$r->{'success'} ) {
		die 'Authority returned generic HTTP error: ',
		  $r->{'status'}, ' ', $r->{'reason'}, "\n";
	}

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
	my $wait = 1;
	for ( my $try = 1; $try <= 10; $try++ ) {
		if ( $try > 1 ) {
			say "next check in $wait seconds";
			sleep $wait;
		}
		
		my ($ch, $h) = $s->_post($url, undef); # POST-as-GET
		$wait = http_retry_parse($h) || $wait * 2;
		$status = $ch->{'status'};

		if ( $wait > $HTTP_RETRY_AFTER_MAX ) {
			$wait = $HTTP_RETRY_AFTER_MAX;
		}

		if ( $status eq 'pending' || $status eq 'processing' ) {
			next;
		}
		elsif ( $status eq 'valid' ) {
			last;
		}
		else {
			die "Challenge did not pass!\n";
		}
	}

	die "Waiting for challenge timed out!"
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
	my $wait = 1;
	for ( my $try = 1; $try <= 10; $try++ ) {
		if ( $try > 1 ) {
			say "next check in $wait seconds";
			sleep $wait;
		}

		my ($polled, $h) = $s->_post($url, undef); # POST-as-GET
		$wait = http_retry_parse($h) || $wait * 2;
		$cert = $polled->{'certificate'};

		if ( $wait > $HTTP_RETRY_AFTER_MAX ) {
			$wait = $HTTP_RETRY_AFTER_MAX;
		}

		if ( !$cert ) {
			next;
		}
		else {
			last;
		}
	}

	die "Waiting for certificate timed out!"
	  if !$cert;

	# POST-as-GET
	my $pemchain = $s->_post($cert, undef, {accept => 'application/pem-certificate-chain'});
	my @chain = _cert_split_chain($pemchain);
	\@chain;
}

sub jws       { $_[0]->{'jws'}; }
sub directory { $_[0]->{'directory'}->{$_[1]} or die "request name \"$_[1]\" not in directory"; }
sub tos       { $_[0]->{'tos'}; }

sub ct_parse {
	if ( !$_[0] ) {
		return;
	}

	(split(/;/, $_[0]))[0];
}

# Parse HTTP Retry-After. Servers can provide either time to wait in
# seconds, or a HTTP date. For now, only support the "re-try in X seconds"
# variant.
sub http_retry_parse {
	my ($h) = @_;
	my $retry = $h->{'retry-after'};

	if ( !defined $retry ) {
		return;
	}

	if ( $retry =~ /^(\d+)$/ ) {
		return int($1);
	}

	return;
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

	state $error_validator = ACNE::Validator->new(
		'type'        => { validator => [\&ACNE::Validator::REGEX, qr/^urn:ietf:params:acme:error:(\w+)$/x] },
		'detail'      => { validator => [\&ACNE::Validator::PRINTABLE] }
	);

	# POST-as-GET when undefined
	my $payload_json = "";
	if ( defined $payload ) {
		# Pretty-print with stable ordering for debugability.
		$payload_json = JSON::PP->new->canonical(1)->pretty(1)->encode($payload);
		# Pretty-printing adds a newline at the end and breaks empty {}
		# requests to some servers.
		chomp($payload_json);
	}

	my ($r, $h, $ct);
	my $MAX_TRIES = 5;
	for ( my $try = 1; $try <= $MAX_TRIES; $try++ ) {
		if ( $try > 1 ) {
			say "Retrying the request (try $try of $MAX_TRIES)";
			sleep 1;
		}

		my $signed = $jws->sign($payload_json, { url => $url, nonce => $s->nonce_shift() }, $use_jwk);
		$r = $http->post($url, { content => $signed, headers => $headers });
		$s->nonce_push($r);
		$h = $r->{'headers'};
		$ct = ct_parse($h->{'content-type'});

		if ( $r->{'success'} ) {
			last;
		}

		if ( defined $ct && $ct eq 'application/problem+json' ) {
			my ($problemdata, $verr) = $error_validator->process(decode_json($r->{'content'}));
			if ( defined $verr ) {
				die "Authority returned an error but the error is bogus!\n", @$verr;
			}

			# Per RFC we should re-try on badNonce (and only badNonce)
			if ( $problemdata->{'type'} eq 'badNonce' && $try < $MAX_TRIES ) {
				say "Authority rejected our nonce";
				next;
			}

			die 'ACME host returned error: ',
			  $problemdata->{'detail'}, ' (', $problemdata->{'type'}, ")\n";
		}

		die 'Authority returned generic HTTP error: ',
		  $r->{'status'}, ' ', $r->{'reason'}, "\n";
	}

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
