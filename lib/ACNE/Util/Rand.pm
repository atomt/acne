package ACNE::Util::Rand;

use 5.014;
use warnings FATAL => 'all';
use autodie;

sub craprand {
	my ($len) = @_;
	my @chars = qw(
	  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
	  a b c d e f g h i j k l m n o p q r s t u v w x y z
	  0 1 2 3 4 5 6 7 8 9 _
	);
	my $rand = '';
	$rand .= $chars[int(rand @chars)] for 1..$len;
	$rand;
}

1;
