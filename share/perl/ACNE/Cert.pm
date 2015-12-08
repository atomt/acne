package ACNE::Cert;

use 5.014;
use warnings;
use autodie;

use ACNE::Common;
use ACNE::Util::File;

use JSON;
use IO::File;
use File::Spec::Functions;


sub _new {
	my ($class, $id, $group, $config) = @_;

	# Load defaults and ca config early to get early feedback.
	my $defaults = groupDefaults($group);
	my $combined; { my %tmp = (%$defaults, %$config); $combined = \%tmp }; # XXX
	$config->{ca} = $combined->{ca}; # renews always have to use ca specified at new time
	my $caconf = caConfig($config->{ca});

	bless {
	  id       => $id,
	  config   => $config,
	  defaults => $defaults,
	  combined => $combined,
	  group    => $group,
	  caconfig => $caconf
	} => $class;
}

# Create new object
sub new {
	my ($class, $id, $group, $config) = @_;

	die "$id already exists under $group\n"
	  if -d dbpath($group, $id);

	# Clean config (removes undefs)
	while ( my($key, $val) = each %$config ) {
		delete $config->{$key} if !defined $val;
	}

	my $s = _new(@_);
	my $combined = $s->{'combined'};

	$s->{'pkey'} = ACNE::Crypto::createPkey($combined->{'key'});

	$s;
}

# Load config from db and return new object
sub load {
	my ($class, $id, $group) = @_;
	my $conf_fp = catfile(dbpath($group, $id), 'config.json');

	my $config;
	{
		local $/;
		my $fh = IO::File->new($conf_fp, 'r')
		  or die "$conf_fp, $!\n";
		my $json_text = <$fh>;
		$config = decode_json($json_text);
	}

	_new(@_, $config);
}

sub fullconfig {
	my ($s) = @_;
	$s->{combined};
}


# XXX validation
sub groupDefaults {
	my ($group) = @_;
	ACNE::Util::File::readPairs(catfile(@ACNE::Common::etcdir, 'group', $group, 'defaults'));
}

# XXX validation
sub caConfig {
	my ($ca) = @_;
	ACNE::Util::File::readPairs(catfile(@ACNE::Common::etcdir, 'ca', $ca, 'config'));
}

sub dbpath {
	my ($group, $id) = @_;
	catdir(@ACNE::Common::libdir, 'db', $group, $id);
}


1;