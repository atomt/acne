package ACNE::Cmd::Account;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use ACNE::CA;
use ACNE::Account;

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

    my ($register, $accept_tos);
    GetOptions(
      'register'     => \$register,
  	  'accept-tos=s' => \$accept_tos
    ) or usage(1);
    my $ca_id = shift @ARGV;

    ACNE::Common::config();
    ACNE::Common::drop_privs();

    if ( !defined $ca_id ) {
      $ca_id = $config->{'defaults'}->{'ca'};
    }

    my $account = ACNE::Account->new;
    my $ca      = ACNE::CA->new($ca_id, $account->keyInit);

    # Register if not registered or --register set
    if ( !$account->_registered($ca_id) or $register ) {
        $account->ca_register($ca, $ca_id);

        # Send an update with ToS if requested
        if ( $accept_tos ) {
            $account->ca_update($ca, $ca_id, $accept_tos);
        }
    }
    # Update
    else {
        $account->ca_update($ca, $ca_id, $accept_tos);
    }

    1;
}

sub usage {
    my ($exitval) = @_;
    my $fd = $exitval ? *STDERR : *STDOUT;
    say $fd 'Usage: acne account <ca>';
    say $fd '       acne account <ca> --accept-tos URL';

    exit $exitval;
}

1;
