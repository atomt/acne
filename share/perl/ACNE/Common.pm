package ACNE::Common;

use 5.014;
use warnings;

use File::Spec::Functions;

our @etcdir = (rootdir(), 'etc', 'acne');
our @libdir = (rootdir(), 'var', 'lib', 'acne');

1;