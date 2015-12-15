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

	my $contact   = $args{'contact'};
	my $agreement = $args{'agreement'};

	my $req = {
		'resource'  => 'new-reg',
		'agreement' => $agreement
	};
	if ( $contact ) {
		$req->{'contact'} = $contact;
	}

	my $r = $s->_post($s->directory('new-reg'), $req);

	my $ret;
	if ( $r->{'status'} == 201 ) {
		say 'Account successfully created';
		$ret = 1;
	}
	elsif ( $r->{'status'} == 409 ) {
		say 'Account already registered';
		$ret = 2;
	}
	else {
		die "Error registering: $r->{status} $r->{reason}\n";
	}

	$ret;
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

	sprintf(
	  "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----",
	  encode_base64($r->{'content'})
	);
}

1;