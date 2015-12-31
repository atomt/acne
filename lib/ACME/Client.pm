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
my $directory_validator = ACNE::Validator->new(
	'new-authz'   => $https_uri,
	'new-cert'    => $https_uri,
	'new-reg'     => $https_uri,
	'revoke-cert' => $https_uri
);


sub new {
	my ($class, %args) = @_;
	my $pkey    = $args{'pkey'}    || croak "pkey parameter missing";
	my $address = $args{'address'} || croak "baseurl parameter missing";

	my $jws = ACME::Client::JWS->new(
	  'pkey' => $pkey
	);
	my $http = HTTP::Tiny->new(
	  'verify_SSL'      => 1,
	  'default_headers' => {
	    'Accept'       => 'application/json',
	    'Content-Type' => 'application/json'
  	  }
  	);

	my $s = bless {
	  'jws'       => $jws,
	  'http'      => $http,
	  'nonce'     => undef, # replay-detection
	  'directory' => undef  # links loaded from /directory
	} => $class;

	# Load directory, containing uris for each api request
	my $r = $s->_get('https://' . $address . '/directory');
	$s->{'directory'} = $directory_validator->process(decode_json($r->{'content'}));

	$s;
}

sub jws       { $_[0]->{'jws'}; }
sub directory { $_[0]->{'directory'}->{$_[1]} or die "request name not in directory"; }

sub _post {
	my ($s, $url, $payload) = @_;
	my $http = $s->{'http'};
	my $jws  = $s->{'jws'};

	my $signed = $jws->sign($payload, { nonce => $s->{'nonce'} });
	my $resp = $http->post($url, { content => $signed });
	$s->_update_nonce($resp);
	$resp;
}

sub _get {
	my ($s, $url) = @_;
	my $http = $s->{'http'};

	my $resp = $http->get($url);
	$s->_update_nonce($resp);
	$resp;
}

# Update nonce
sub _update_nonce {
	my ($s, $resp) = @_;

	my $headers = $resp->{'headers'};
	if ( my $nonce = $headers->{'replay-nonce'} ) {
		$s->{'nonce'} = $nonce;
	}
	else {
		die "No nonce could be aquired! $resp->{status} $resp->{reason}\n";
	}
}



sub new_reg {
	my ($s, %args) = @_;
	my $email   = $args{'email'};
	my $tel     = $args{'tel'};
	my $created = 0;

	my @contact;
	push @contact, 'mailto:' . $email if defined $email;
	push @contact, 'tel:' . $tel      if defined $tel;

	my $req = { 'resource' => 'new-reg' };
	if ( @contact ) {
		$req->{'contact'} = \@contact;
	}

	my $r = $s->_post($s->directory('new-reg'), $req);

	my $status = $r->{'status'};
	if ( $status == 201 ) {
		$created = 1;
	}
	elsif ( $status != 409 ) {
		_check_error($r);
		die "Error registering: $status $r->{reason}\n";
	}

	my $tos = do { my $links = _links($r->{'headers'}); $links->{'terms-of-service'} };
	my $loc = $r->{'headers'}->{'location'};

	$tos = ACNE::Validator::PRINTABLE($tos) if defined $tos;
	$loc = ACNE::Validator::PRINTABLE($loc) if defined $loc;

	($created, $loc, $tos);
}

sub reg {
	my ($s, $uri, %args) = @_;
	my $email     = $args{'email'};
	my $tel       = $args{'tel'};
	my $agreement = $args{'agreement'};

	my @contact;
	push @contact, 'mailto:' . $email if defined $email;
	push @contact, 'tel:' . $tel     if defined $tel;

	my $req = { 'resource' => 'reg' };
	if ( @contact ) {
		$req->{'contact'} = \@contact;
	}
	if ( defined $agreement ) {
		$req->{'agreement'} = $agreement;
	}

	my $r = $s->_post($uri, $req);

	if ( $r->{'status'} != 202 ) {
		_check_error($r);
		die "Error updating: $r->{status} $r->{reason}\n";
	}

	1;
}

sub new_authz {
	my ($s, $domain) = @_;

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

	my $req = {
		'resource'   => 'new-authz',
		'identifier' => {
			'type'  => 'dns',
			'value' => $domain
		}
	};

	my $r = $s->_post($s->directory('new-authz'), $req);
	my $status = $r->{'status'};
	my $h      = $r->{'headers'};
	my $ct     = $h->{'content-type'};

	if ( $status != 201 ) {
		_check_error($r);
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

	# A dict of strings, type = dns and value dnsname
	my $identifier = $identifier_validator->process(delete $json->{'identifier'});

	# The challenges server supports for this dns name.
	# Validation of challenge is left to the code handling challenges.
	my $challenges = delete $json->{'challenges'}
	  or die "No challenges in json from server\n";

	if ( ref $challenges ne 'ARRAY' ) {
		die "challenges in json from server not a list\n";
	}

	# List of lists. If not set all challenges must be met.
	delete $json->{'combinations'};

	# We should be left with: status (default pending), expires (RFC3339, optional)
	my $rest = $validator->process($json);

	if ( $rest->{'status'} ne 'pending' ) {
		die "status of authorization is not pending\n";
	}

	@$challenges;
}

sub challenge {
	my ($s, $url, $auth) = @_;
	my $req = { 'resource' => 'challenge', 'keyAuthorization' => $auth };

	my $r = $s->_post($url, $req);
	if ( $r->{'status'} != 202 ) {
		_check_error($r);
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

	my $r = $s->_get($url);
	my $status = $r->{'status'};
	my $h      = $r->{'headers'};
	my $ct     = $h->{'content-type'};

	if ( $status != 202 ) {
		_check_error($r);
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
	say Dumper($json);
	$json->{'status'};
}

sub new_cert {
	my ($s, $csr) = @_;

	my $req = {
	  'resource' => 'new-cert',
	  'csr'      => encode_base64url($csr)
	};

	my $r = $s->_post($s->directory('new-cert'), $req);

	if ( $r->{'status'} != 201 ) {
		_check_error($r);
		die "Error signing certificate: $r->{status} $r->{reason}\n";
	}

	my @chain;
	push @chain, _cert_format($r->{'content'});

	my $headers = $r->{'headers'};
	my $loc   = $headers->{'location'};
	my $links = _links($headers);
	my $uri   = $links->{'up'};
	$s->_cert_walk_link($uri, \@chain);

	($loc, \@chain);
}

sub _check_error {
	my ($r) = @_;

	# Stuff we output to terminal, so be careful.
	state $error_validator = ACNE::Validator->new(
		'type'        => { validator => [\&ACNE::Validator::REGEX, qr/^urn:acme:error:(\w+)$/x] },
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

sub _cert_walk_link {
	my ($s, $uri, $chain) = @_;
	my $max = 10;

	while ( $uri && @$chain < $max ) {
		my ($cert, $next) = $s->_cert_get($uri);
		$uri = $next;
		push @$chain, _cert_format($cert);
	}

	die "Recursion limit reached at $uri\n"
	  if $uri;

	1;
}

sub _cert_get {
	my ($s, $uri) = @_;
	my $http = $s->{'http'};

	my $r = $http->get($uri);

	if ( $r->{'status'} != 200 ) {
		_check_error($r);
		die "_cert_get $r->{status} $r->{reason}";
	}

	my $links = _links($r->{'headers'});
	my $next  = $links->{'up'};

	return ($r->{'content'}, $next);
}

sub _cert_format {
	sprintf(
	  "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----",
	  encode_base64($_[0])
	);
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
