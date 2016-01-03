package ACNE::OpenSSL::Date;

use 5.014;
use warnings FATAL => 'all';

use POSIX ();
use IPC::Open3 qw(open3);

#notBefore=..
#notAfter=Mar 25 23:38:00 2016 GMT
my $dates_re = qr/^notBefore=([\w\ :]+)\nnotAfter=([\w\ :]+)\n$/x;
my $date_re = qr/^(?<mon>\w+)\s+(?<day>\d+)\s+(?<hour>\d+):(?<min>\d+):(?<sec>\d+)\s+(?<year>\d{4})\s+GMT$/x;
my %abbr = (Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4, Jun => 5, Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11);

sub x509_dates {
	my ($cert) = @_;
    my @ret;

	my ($writer, $reader);
	my $pid = open3($writer, $reader, '>&STDERR', 'openssl', 'x509', '-noout', '-dates');
	print $writer $cert;
	close $writer;
	my $out = do { local $/; <$reader> };

	if ( $out =~ $dates_re ) {
        @ret = (
            toEpoch($1),
            toEpoch($2)
        );
	}
	else {
		die "did not grok openssl output";
	}

	waitpid $pid, 0;
	die "OpenSSL failed reading certificate data" if $? >> 8 != 0;

	@ret;
}

# Hack-parse date and time from issued cert. We could pull in DateTime for
# this but its one field and it's always in the same format and always GMT.
# Until we need date parsing somewhere else just hack it.
#Dec 26 23:38:00 2015 GMT
sub toEpoch {
	my ($in) = @_;

	if ( $in =~ $date_re ) {
		my @parsed = (
		  int($+{sec}),
		  int($+{min}),
		  int($+{hour}),
		  int($+{day}),
		  $abbr{$+{mon}},
		  $+{year} - 1900,
		  -1,
		  -1,
		  0
		);
		return int(POSIX::strftime('%s', @parsed));
	}
	else {
		die "did not grok";
	}
}

1;
