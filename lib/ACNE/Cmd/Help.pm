package ACNE::Cmd::Help;

use 5.014;
use warnings FATAL => 'all';
use autodie;

sub run {
	say 'acme new example.com -d example.com -d www.example.com --for nginx [--ca le]';
	say 'acme renew-auto';
	say 'acme list';
	say 'acme remove example.com';
	say 'acme revoke example.com';
}

1;