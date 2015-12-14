package ACME::Client;

use 5.014;
use warnings FATAL => 'all';
use autodie;
use Carp qw(croak carp);

use ACME::Client::JWS;
use JSON;
use HTTP::Tiny;
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

	my $signed = $jws->sign($payload, {
	  nonce => $nonce
	});

	my $response = $http->post($url, {
	  content => $signed
	});

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

	return ($status, $reason, decode_json($response->{'content'}));
}

sub accountRegister {
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

	my ($code, $reason, $response) = $s->_post($baseurl . '/acme/new-reg', $req);

	my $ret;
	if ( $code == 201 ) {
		say 'Account successfully created';
		$ret = 1;
	}
	elsif ( $code == 409 ) {
		say 'Account already registered';
		$ret = 2;
	}
	else {
		die "Error registering: $code $reason\n";
	}

	$ret;
}

sub domainAuth {
	my ($s, $domain) = @_;
	my $baseurl = $s->{'baseurl'};

	my $req = {
		'resource'   => 'new-authz',
		'identifier' => {
			'type'  => 'dns',
			'value' => $domain
		}
	};

	my ($code, $reason, $response) = $s->_post($baseurl . '/acme/new-authz', $req);

	if ( $code != 201 ) {
		die "Error requesting challenge: $code $reason\n";
	}

	#say Dumper($response);

	$response->{'challenges'};
}


1;