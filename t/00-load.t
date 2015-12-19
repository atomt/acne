#!perl -T
use 5.014;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'ACNE' ) || print "Bail out!\n";
}

diag( "Testing ACNE $ACNE::VERSION, Perl $], $^X" );
