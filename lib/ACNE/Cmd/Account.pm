package ACNE::Cmd::Account;

use 5.014;
use warnings FATAL => 'all';
use autodie;

use ACNE::Common qw($config);
use ACNE::CA;
use ACNE::Account;

use Getopt::Long;

# acne account <ca>
# acne account <ca> --accept-tos
sub run {
    my $cmd   = shift @ARGV;
    my $ca_id = shift @ARGV;

    die "CA argument is missing\n"
      if !defined $ca_id;

    my $accept_tos;
    GetOptions(
  	  'accept-tos=s' => \$accept_tos
    ) or usage(1);

    ACNE::Common::config();
    ACNE::Common::drop_privs();

    my $account = ACNE::Account->new;
    my $ca      = ACNE::CA->new($ca_id, $account->keyInit);

    if ( !$accept_tos ) {
      $account->register($ca, $ca_id);
    }
    else {
      $account->accept_tos($ca, $ca_id, $accept_tos);
    }
}

sub usage {
    my ($exitval) = @_;
    my $fd = $exitval ? *STDERR : *STDOUT;
    say $fd 'Usage: acne account <ca>';
    say $fd '       acne account <ca> --accept-tos URL';

    exit $exitval;
}

1;
