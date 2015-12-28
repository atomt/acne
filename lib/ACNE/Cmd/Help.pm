package ACNE::Cmd::Help;

use 5.014;
use warnings FATAL => 'all';
use autodie;

sub run {
	say '';
	say 'acne init';
	say ' Set up store according to configuration';
	say '';
	say 'acne account';
	say ' Creates or updates accunt at Certificate Authority';
	say '';
	say 'acne new <certname> -d <domain1> [-d <domain2> ..]';
	say ' Create a new certificate entry, issues and installs it';
	say '';
	say 'acne renew <certname1> [<certname2> ..]';
	say ' Renew a existing certificate entry';
	say '';
	say 'acne renew-auto';
	say ' Like renew but auto-selects certificates based on upcoming expiry';
	say '';
	say 'acne install <certname1> [<certname2> ..]';
	say ' Re-install cert that has previously been issued';
	say '';
	say 'For detailed information on each command, run acne <command> --help';
	say '';
}

1;
