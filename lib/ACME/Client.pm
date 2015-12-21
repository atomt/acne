package ACME::Client;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACME::Client::JWS;
use JSON;
use HTTP::Tiny;
use MIME::Base64 qw(encode_base64 encode_base64url);

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
	$s->{'directory'} = decode_json($r->{'content'});

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
	my $email = $args{'email'};
	my $tel   = $args{'tel'};

	my @contact;
	push @contact, 'email:' . $email if defined $email;
	push @contact, 'tel:' . $tel     if defined $tel;

  my $req = { 'resource' => 'new-reg' };
	if ( @contact ) {
		$req->{'contact'} = \@contact;
	}

	my $r = $s->_post($s->directory('new-reg'), $req);
	my $tos = do { my $links = _links($r->{'headers'}); $links->{'terms-of-service'} };
	my $loc = $r->{'headers'}->{'location'};

	if ( $r->{'status'} == 201 ) {
		say 'Account successfully created';
	}
	elsif ( $r->{'status'} == 409 ) {
		say 'Account already registered';
	}
	else {
		die "Error registering: $r->{status} $r->{reason}\n";
	}

	($loc, $tos);
}

sub reg {
	my ($s, $uri, %args) = @_;
	my $email     = $args{'email'};
	my $tel       = $args{'tel'};
	my $agreement = $args{'agreement'};

	my @contact;
	push @contact, 'email:' . $email if defined $email;
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
		die "Error updating: $r->{status} $r->{reason}\n";
	}

	1;
}

sub new_authz {
	my ($s, $domain) = @_;

	my $req = {
		'resource'   => 'new-authz',
		'identifier' => {
			'type'  => 'dns',
			'value' => $domain
		}
	};

	my $r = $s->_post($s->directory('new-authz'), $req);

	if ( $r->{'status'} != 201 ) {
		die "Error requesting challenge: $r->{status} $r->{reason}\n";
	}

	my $json = decode_json($r->{'content'});
	my @challenges = @{$json->{'challenges'}};
	if ( @challenges == 0 ) {
		die "No challenges recieved from ACME server\n";
	}

	# Clean up
	# FIXME do we really have to
	for my $challenge ( @challenges ) {
		$challenge->{'token'} =~ s![^A-Za-z0-9_\-]!_!g;
	}

	@challenges;
}

sub challenge {
	my ($s, $url, $auth) = @_;
	my $req = { 'resource' => 'challenge', 'keyAuthorization' => $auth };

	my $r = $s->_post($url, $req);
	if ( $r->{'status'} != 202 ) {
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

	if ( $r->{'status'} != 202 ) {
		die "Error polling challenge: $r->{status} $r->{reason}\n";
	}

	my $json = decode_json($r->{'content'});
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
		die "Error signing certificate: $r->{status} $r->{reason}\n";
	}

	# FIXME should return the URL reported in the headers for later
	# re-dowloading as well.

	my @chain;
	push @chain, _cert_format($r->{'content'});

	my $links = _links($r->{'headers'});
	my $uri   = $links->{'up'};
	$s->_cert_walk_link($uri, \@chain);

	@chain;
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
