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
	my $pkey      = $args{'pkey'}      || croak "pkey parameter missing";
	my $kid       = $args{'kid'};
	my $directory = $args{'directory'} || croak "directory parameter missing";

	my $jws = ACME::Client::JWS->new(
	  'pkey' => $pkey,
		'kid'  => $kid
	);
	my $http = HTTP::Tiny->new(
	  'verify_SSL'      => 1,
	  'default_headers' => {
	    'Accept'       => 'application/json',
	    'Content-Type' => 'application/jose+json'
  	  }
  	);

	my $s = bless {
	  'jws'           => $jws,
	  'http'          => $http,
	  'nonce'         => undef, # replay-detection
	  'directory'     => undef,  # links loaded from /directory
		'tos'           => undef,
		'directory_url' => $directory
	} => $class;

	$s->_directory_load();
}

sub _directory_load {
	my ($s) = @_;
	my $http      = $s->{'http'};
	my $directory = $s->{'directory_url'};

	# Load directory, containing uris for each supported api request
	my $r = $http->get($directory);
	my $directory_raw = decode_json($r->{'content'});
	if ( !exists $directory_raw->{'newOrder'} ) {
		die "Failed to detect presence of ACMEv2 support in CA directory\n";
	}

	$s->{'directory'} = $directory_validator->process($directory_raw);
	my $meta = $directory_meta_validator->process($directory_raw->{'meta'});
	$s->{'tos'} = $meta->{'termsOfService'};
	$s->_update_nonce($r);

	return $s;
}

sub jws       { $_[0]->{'jws'}; }
sub directory { $_[0]->{'directory'}->{$_[1]} or die "request name \"$_[1]\" not in directory"; }
sub tos       { $_[0]->{'tos'}; }

sub _post {
	my ($s, $url, $payload) = @_;
	my $http = $s->{'http'};
	my $jws  = $s->{'jws'};

	$s->_update_nonce(undef);
	my $signed = $jws->sign($payload, { url => $url, nonce => $s->{'nonce'} });
	my $resp = $http->post($url, { content => $signed });

	$s->{'nonce'} = undef;
	$s->_update_nonce($resp);
	$resp;
}

sub _get {
	my ($s, $url) = @_;
	my $http = $s->{'http'};

	$s->_update_nonce(undef);
	my $resp = $http->get($url);
	$s->{'nonce'} = undef;
	$s->_update_nonce($resp);
	$resp;
}

# Update nonce
sub _update_nonce {
	my ($s, $resp) = @_;

	# Try and find it in passed response (often available with ACMEv1)
	if ( defined $resp ) {
		my $headers = $resp->{'headers'};
		if ( my $nonce = $headers->{'replay-nonce'} ) {
			$s->{'nonce'} = $nonce;
			return 1;
		}
	}

	# If we didnt get it, and dont have it, get new
	if ( defined $s->{'nonce'} ) {
		return 1;
	}

	$s->{'nonce'} = $s->_get_nonce;
}

sub _get_nonce {
	my ($s) = @_;
	my $http = $s->{'http'};
	my $url  = $s->directory('newNonce');

	my $resp = $http->head($url);
	my $headers = $resp->{'headers'};
	if ( my $nonce = $headers->{'replay-nonce'} ) {
		return $nonce;
	}

	die "No Replay-Nonce in CA response! url: $url";
}

sub new_reg {
	my ($s, %args) = @_;
	my $api     = $s->{'api'};
	my $email   = $args{'email'};
	my $tel     = $args{'tel'};
	my $created = 0;

	my @contact;
	push @contact, 'mailto:' . $email if defined $email;
	push @contact, 'tel:' . $tel      if defined $tel;

	my $req = {};
	if ( @contact ) {
		$req->{'contact'} = \@contact;
	}
	$req->{'termsOfServiceAgreed'} = JSON::PP::true;

	my $r = $s->_post($s->directory('newAccount'), $req);

	my $status = $r->{'status'};
	if ( $status == 201 ) {
		$created = 1;
	}
	elsif ( $status != 409 ) {
		$s->_check_error($r);
		die "Error registering: $status $r->{reason}\n";
	}

	my $loc = $r->{'headers'}->{'location'};
	$loc = ACNE::Validator::PRINTABLE($loc) if defined $loc;

	($created, $loc);
}

sub reg {
	my ($s, $uri, %args) = @_;
	my $email     = $args{'email'};
	my $tel       = $args{'tel'};
	my $agreement = $args{'agreement'};

	my @contact;
	push @contact, 'mailto:' . $email if defined $email;
	push @contact, 'tel:' . $tel     if defined $tel;

	my $req = {};
	if ( @contact ) {
		$req->{'contact'} = \@contact;
	}
	if ( $agreement ) {
		$req->{'termsOfServiceAgreed'} = JSON::PP::true;
	}

	my $r = $s->_post($uri, $req);

	if ( $r->{'status'} != 200 ) {
		$s->_check_error($r);
		die "Error updating: $r->{status} $r->{reason}\n";
	}

	1;
}

sub get_reg {
	my ($s) = @_;

	my $r = $s->_post($s->directory('newAccount'), {
		onlyReturnExisting => JSON::PP::true
	});
	my $status = $r->{'status'};
	my $h      = $r->{'headers'};
	my $ct     = $h->{'content-type'};

	if ( $status != 200 ) {
		$s->_check_error($r);
		die "Error requesting account info: $r->{status} $r->{reason}\n";
	}

	if ( !defined $ct ) {
		die "No Content-Type provided by server\n";
	}

	if ( $ct ne 'application/json' ) {
		my $printable = ACNE::Validator::PRINTABLE($ct);
		die "Got Content-Type \"$printable\", not application/json as expected\n";
	}

	return decode_json($r->{'content'});
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
	my $ct     = $h->{'content-type'};

	if ( $status != 201 ) {
		$s->_check_error($r);
		die "Error requesting challenge: $status $r->{reason}\n";
	}

	if ( !defined $ct ) {
		die "No Content-Type provided by server\n";
	}

	if ( $ct ne 'application/json' ) {
		my $printable = ACNE::Validator::PRINTABLE($ct);
		die "Got Content-Type \"$printable\", not application/json as expected\n";
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
			$s->_check_error($r);
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

	say "LOCATION: $location";

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
		$s->_check_error($r);
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
		$s->_check_error($r);
		die "Error polling challenge: $status $r->{reason}\n";
	}

	if ( !defined $ct ) {
		die "No Content-Type provided by server\n";
	}

	if ( $ct ne 'application/json' ) {
		my $printable = ACNE::Validator::PRINTABLE($ct);
		die "Got Content-Type \"$printable\", not application/json as expected\n";
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
		$s->_check_error($r);
		die "Error signing certificate: $r->{status} $r->{reason}\n";
	}

	# Poll the order url to see if there is a certificate to fetch
	$r = $s->_post($order_url, undef); # POST-as-GET
	if ( $r->{'status'} != 200 ) {
		$s->_check_error($r);
		die "Error polling order status: $r->{status} $r->{reason}\n";
	}

	my $order_polled = decode_json($r->{'content'});
	my $cert_url = $order_polled->{'certificate'};
	if ( !$cert_url ) {
		die "No certificate!";
	}

	$r = $s->_post($cert_url, undef); # POST-as-GET
	if ( $r->{'status'} != 200 ) {
		$s->_check_error($r);
		die "Error getting certificate: $r->{status} $r->{reason}\n";
	}

	my @chain = _cert_split_chain($r->{'content'});
	\@chain;
}

sub _check_error {
	my ($s, $r) = @_;
	my $api = $s->{'api'};

	# Stuff we output to terminal, so be careful.
	state $error_validator = ACNE::Validator->new(
		'type'        => { validator => [\&ACNE::Validator::REGEX, qr/^urn:ietf:params:acme:error:(\w+)$/x] },
		'detail'      => { validator => [\&ACNE::Validator::PRINTABLE] },
		'status'      => { validator => [\&ACNE::Validator::INT] }
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
