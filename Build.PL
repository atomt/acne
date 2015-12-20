use 5.014;
use warnings;

use Module::Build;

my $release_status = 'unstable';

my $build = Module::Build->new(
	module_name        => 'Acne',
	license            => 'gpl_2',
	dist_author        => q{Andre Tomt <andre@tomt.net>},
	dist_version_from  => 'lib/ACNE.pm',
	dist_abstract      => q{ACME/Let's Encrypt client},
	release_status     => $release_status,
	configure_requires => {
		'Module::Build' => 0
	},
	build_requires => {
		'Test::More' => 0,
	},
	requires => {
		'HTTP::Tiny'      => 0.012,   # Core since 5.10
		'IO::Socket::SSL' => 1.56,
		'Net::SSLeay'     => 1.49,
		'JSON::PP'        => 2.27105, # Core since 5.14
	},
	add_to_cleanup => [ 'Acne-*' ],
	etc_files => {
		'etc/config.sample' => 'etc/config.sample'
	},
	script_files => ['bin/acne'],
);

$build->add_build_element('etc');
if ( !$build->install_path('etc') ) {
	if ( $build->install_base ) {
	    $build->install_path( 'etc' => $build->install_base . '/etc/acne' );
	}
	else {
	    $build->install_path( 'etc' => '/etc/acne' );
	}
}

$build->dispatch('manifest');
$build->dispatch('distmeta');
$build->create_build_script;