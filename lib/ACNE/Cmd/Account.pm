package ACNE::Cmd::Account;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use ACNE::CA;
use ACNE::Validator;

use Getopt::Long;

# Automatic mode: Register if new, update otherwise
# acne account <ca>
#
# Force registration even if we think we're registered
# acne account <ca> --register
#
# Accept CA ToS
# acne account <ca> --accept-tos
sub run {
    my $cmd   = shift @ARGV;

    my ($register, $accept_tos, $arg_help);
    GetOptions(
      'register'   => \$register,
      'accept-tos' => \$accept_tos,
      'help'       => \$arg_help
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

    say "Selected Certificate Authority $ca_id.";

    my $ca = ACNE::CA->new($ca_id);

    # Load local account information
    if ( !$ca->account_exists_db ) {
        say 'Generating new account key.';
        $ca->create_db;
    }
    $ca->initialize;

    # Config
    my $aconf = $config->{'account'}
	  or die "Account has no valid configuration\n";

	my @contact;
	push @contact, 'mailto:' . $aconf->{'email'} if defined $aconf->{'email'};
	push @contact, 'tel:'    . $aconf->{'tel'}   if defined $aconf->{'tel'};

    # Register
    if ( !$ca->registered_db ) {
        my $ca_tos = $ca->tos;

        if ( $ca_tos && !$accept_tos ) {
            say '';
		    say 'This Certificate Authority has a Terms of Service that you need to agree';
            say 'to before you can use it. This document can be viewed here:';
            say '';
            say $ca_tos;
		    say '';
		    say "Approve it using this command: `acne account $ca_id --accept-tos`";
		    say 'before issuing any certificates using this authority';
		    say '';

            exit 1;
        }

        my %req;
        $req{contact} = \@contact if @contact > 0;

        if ( $accept_tos ) {
            say "Accepting the following Terms of service:";
            say $ca_tos;
            say '';
            $req{termsOfServiceAgreed} = 1;
        }
        $ca->newAccount(%req);
        $ca->registered_db_set();

        say 'A new account was created at the Certificate Authority.';
    }
    # Update
    else {
        my %req;
        $req{contact} = \@contact if @contact > 0;

        # Push update
        $ca->updateAccount(%req);
        say "Account updated at the Certificate Authority.";
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
