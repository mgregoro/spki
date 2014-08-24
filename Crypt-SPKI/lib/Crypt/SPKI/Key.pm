#
# SocialPKI
# (c) Michael Gregorowicz 2014
#
# A base class for Crypt::SPKI key objects.

# ABSTRACT: Base class for individual keys

package Crypt::SPKI::Key;
use strict;
use warnings;

use Mojo::Base 'Crypt::SPKI::ByteStream';

# must be instantiated with a hex encoded key
sub new {
    my ($class, $key) = @_;

    my $bytes;
    while ($key =~ /([0-9a-f]{2})/oig) {
        $bytes .= pack('H2', $1);
    }

    return $class->SUPER::new($bytes);
}

1;
