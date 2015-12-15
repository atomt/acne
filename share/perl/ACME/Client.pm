package ACME::Client;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACME::Client::JWS;
use JSON;
use HTTP::Tiny;
use MIME::Base64 qw(encode_base64 encode_base64url);
use Data::Dumper;

sub new {
	my ($class, %args) = @_;
	my $pkey    = $args{'pkey'}    || croak "pkey parameter missing";
	my $baseurl = $args{'baseurl'} || croak "baseurl parameter missing";

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

	bless {
	  baseurl => $baseurl,
	  jws     => $jws,
	  http    => $http,
	  nonce   => undef
	} => $class;
}

sub jws { $_[0]->{'jws'}; }

sub nonceInit {
	my ($s) = @_;
	my $baseurl = $s->{'baseurl'};
	my $http    = $s->{'http'};
	my $fullurl = $baseurl . '/directory';

	my $response = $http->head($fullurl);
	my $status   = $response->{'status'};
	my $reason   = $response->{'reason'};
	my $headers  = $response->{'headers'};

	if ( $status != 200 ) {
		die "HEAD $fullurl failed: $status $reason\n";
	}

	if ( my $nonce = $headers->{'replay-nonce'} ) {
		$s->{'nonce'} = $nonce;
		return 1;
	}

	die "No nonce could be aquired! $status $reason\n";
}

sub _post {
	my ($s, $url, $payload) = @_;
	my $http  = $s->{'http'};
	my $jws   = $s->{'jws'};
	my $nonce = $s->{'nonce'};

	my $signed   = $jws->sign($payload, { nonce => $nonce });
	my $response = $http->post($url, { content => $signed });
	my $status   = $response->{'status'};
	my $reason   = $response->{'reason'};
	my $headers  = $response->{'headers'};

	# Update nonce
	if ( my $nonce = $headers->{'replay-nonce'} ) {
		$s->{'nonce'} = $nonce;
	}
	else {
		die "No nonce could be aquired! $status $reason\n";
	}

	return ($status, $reason, $response->{'content'});
}

sub _get {
	my ($s, $url) = @_;
	my $http     = $s->{'http'};
	my $nonce    = $s->{'nonce'};
	my $response = $http->get($url);

	my $status  = $response->{'status'};
	my $reason  = $response->{'reason'};
	my $headers = $response->{'headers'};

	# Update nonce
	if ( my $nonce = $headers->{'replay-nonce'} ) {
		$s->{'nonce'} = $nonce;
	}
	else {
		die "No nonce could be aquired! $status $reason\n";
	}

	return ($status, $reason, $response->{'content'});
}

sub new_reg {
	my ($s, %args) = @_;
	my $baseurl = $s->{'baseurl'};

	my $contact   = $args{'contact'};
	my $agreement = $args{'agreement'};

	my $req = {
		'resource'  => 'new-reg',
		'agreement' => $agreement
	};
	if ( $contact ) {
		$req->{'contact'} = $contact;
	}

	my ($status, $reason, $response) = $s->_post($baseurl . '/acme/new-reg', $req);

	my $ret;
	if ( $status == 201 ) {
		say 'Account successfully created';
		$ret = 1;
	}
	elsif ( $status == 409 ) {
		say 'Account already registered';
		$ret = 2;
	}
	else {
		die "Error registering: $status $reason\n";
	}

	$ret;
}

sub new_authz {
	my ($s, $domain) = @_;
	my $baseurl = $s->{'baseurl'};

	my $req = {
		'resource'   => 'new-authz',
		'identifier' => {
			'type'  => 'dns',
			'value' => $domain
		}
	};

	my ($status, $reason, $content) = $s->_post($baseurl . '/acme/new-authz', $req);

	if ( $status != 201 ) {
		die "Error requesting challenge: $status $reason\n";
	}

	my $json = decode_json($content);
	my @challenges = @{$json->{'challenges'}};
	if ( @challenges == 0 ) {
		die "No challenges recieved from ACME server\n";
	}

	# Clean up
	for my $challenge ( @challenges ) {
		$challenge->{'token'} =~ s![^A-Za-z0-9_\-]!_!g;
	}

	@challenges;
}

sub challenge {
	my ($s, $url, $auth) = @_;
	my $req = { 'resource' => 'challenge', 'keyAuthorization' => $auth };

	my ($status, $reason, $content) = $s->_post($url, $req);
	if ( $status != 202 ) {
		die "Error triggering challenge: $status $reason\n";
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

	my ($status, $reason, $content) = $s->_get($url);

	if ( $status != 202 ) {
		die "Error polling challenge: $status $reason\n";
	}

	my $json = decode_json($content);
	$json->{'status'};
}

sub new_cert {
	my ($s, $csr) = @_;
	my $baseurl = $s->{'baseurl'};

	my $req = {
	  'resource' => 'new-cert',
	  'csr'      => encode_base64url($csr)
	};

	my ($status, $reason, $content) = $s->_post($baseurl . '/acme/new-cert', $req);

	if ( $status != 201 ) {
		die "Error signing certificate: $status $reason\n";
	}

	sprintf(
	  "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----",
	  encode_base64($content)
	);
}

1;