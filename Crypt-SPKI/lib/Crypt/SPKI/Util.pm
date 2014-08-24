#
# SocialPKI
# (c) Michael Gregorowicz 2014
#
# A miscellaneous utility class for SocialPKI

package Crypt::SPKI::Util;
use strict;
use warnings;

use Mojo::Base 'Exporter';
use Crypt::SPKI::ByteStream;
use Crypt::Sodium;

our @EXPORT_OK = qw/
    cb_nonce    
    cs_nonce
/;

sub cb_nonce {
    return Crypt::SPKI::ByteStream->new(crypto_box_nonce());
}

sub cs_nonce {
    return Crypt::SPKI::ByteStream->new(crypto_stream_nonce());
}

1;
