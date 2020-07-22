package ACNE::Cmd::Account;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use ACNE::CA;
use ACNE::Account;
use ACNE::Validator;

use Getopt::Long;

# Automatic mode: Register if new, update otherwise
# acne account <ca>
#
# Force registration even if we thing we're registered
# acne account <ca> --register
#
# Accept CA ToS - basicly an update
# acne account <ca> --accept-tos <url>
sub run {
    my $cmd   = shift @ARGV;

    my ($register, $accept_tos, $arg_help);
    GetOptions(
      'register'     => \$register,
      'accept-tos=s' => \$accept_tos,
      'help'         => \$arg_help
	) or usage_err();

    my $ca_id = shift @ARGV;

    if ( $arg_help ) {
		usage();
	}

    if ( @ARGV ) {
        say STDERR "Unknown arguments.";
        usage_err();
    }

    ACNE::Common::config();
    ACNE::Common::drop_privs();

    if ( !defined $ca_id ) {
        $ca_id = $config->{'defaults'}->{'ca'};
    }
    else {
        $ca_id = ACNE::Validator::WORD($ca_id);
    }

    my $account = ACNE::Account->new;
    my $ca      = ACNE::CA->new($ca_id, $account);
    my $ca_tos  = $ca->tos();
    my $account_tos = $account->tos($ca_id);
    my $require_accept = 0;

    # Check if CA has a TOS
    if ( !$accept_tos && $ca_tos ) {
        # Check if Account has a accepted TOS
        if ( $account_tos ) {
            # Check if CA has updated the TOS
            if ( $account_tos ne $ca_tos ) {
                say '';
                say 'This Certificate Authority has a updated its Terms of Service location.';
                say "This document can be viewed here: $ca_tos";
                say '';
                say "Approve it using this command: acne account $ca_id --accept-tos <the URI above>";
                say '';

                $require_accept = 1;
            }
        }
        else {
            say '';
		    say 'This Certificate Authority has a Terms of Service that you need to agree to before you can use it.';
	    	say "This document can be viewed here: $ca_tos";
		    say '';
		    say "Approve it using this command: acne account $ca_id --accept-tos <the URI above>";
		    say 'before issuing any certificates using this authority';
		    say '';

            $require_accept = 1;
        }
    }

    if ( $require_accept && !$accept_tos ) {
        say STDERR 'Will not continue unless Certificate Authority Terms of Service have been accepted with --accept-tos'
        exit 1;
    }

    # Register if not registered or --register set
    if ( !$account->_registered($ca_id) or $register ) {
        $account->ca_register($ca, $ca_id);
    }
    # Update
    else {
        $account->ca_update($ca, $ca_id);
    }

    1;
}

sub usage_err {
	say STDERR 'Try \'acne account --help\' for more information.';
	exit 1;
}

sub usage {
    say 'Usage: acne account [<ca>]';
    say '       acne account [<ca>] --accept-tos URL';
    say '';
    say 'Creates or updates account at specified Certificate Authority.';
    say 'If no CA is specified, the default one according to the configuration is';
    say 'used.';
    exit 0;
}

1;
