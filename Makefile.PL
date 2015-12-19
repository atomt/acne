use 5.014;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'ACNE',
    AUTHOR           => q{Andre Tomt <andre@tomt.net>},
    VERSION_FROM     => 'lib/ACNE.pm',
    ABSTRACT_FROM    => 'lib/ACNE.pm',
    LICENSE          => 'gpl_2',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.014,
    META_MERGE => {
        dynamic_config => 0,
        'meta-spec'    => {version => 2},
        no_index       => {directory => ['examples', 't']},
        prereqs        => {runtime => {requires => {perl => '5.014'}}},
        resources => {
            bugtracker => {web => 'https://github.com/atomt/acne/issues'},
            repository => {
                type => 'git',
                url  => 'https://github.com/atomt/acne.git',
                web  => 'https://github.com/atomt/acne'
            },
        },
    },
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
        'HTTP::Tiny'      => 0.012,   # Core since 5.10
        'IO::Socket::SSL' => 1.56,
        'Net::SSLeay'     => 1.49,
        'JSON::PP'        => 2.27105, # Core since 5.14
    },
    EXE_FILES => ['script/acne', 'script/acne-init', 'script/acne-new'],
    dist  => { COMPRESS => 'bzip2 -9f', SUFFIX => '.bz2', },
    clean => { FILES => 'acne-*' },
);
