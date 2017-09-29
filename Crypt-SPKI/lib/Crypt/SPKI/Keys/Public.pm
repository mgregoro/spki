#
# SocialPKI
# (c) 2014 Michael Gregorowicz
#
# Class which contains both Encryption and Signing Public Keys
#

# ABSTRACT: Key set class encapsulating a public encryption key, and a public signing key

package Crypt::SPKI::Keys::Public;
use warnings;
use strict;

use Mojo::Base 'Crypt::SPKI::Key::Set';
use MIME::Base64 qw/encode_base64url/;

use Crypt::SPKI::Keys::Public::Enc;
use Crypt::SPKI::Keys::Public::Sign;

has aa_header => '----- BEGIN SOCIALPKI PUBLIC KEY -----';
has aa_footer => '----- END SOCIALPKI PUBLIC KEY -----';

sub thumbprint {
    my ($self) = @_;
    return encode_base64url($self->enc->crypto_hash_bytes($self->sign->crypto_hash_bytes));
}

sub thumbprint_short {
    my ($self) = @_;
    return substr($self->thumbprint, -8);
}

sub fingerprint {
    my ($self) = @_;

    my $fingerprint = uc(substr($self->enc->crypto_hash_sum($self->sign->crypto_hash_bytes), 96, 32));

    # separate with :'s
    my ($separated, $offset) = (undef, 0);
    while ($offset < 32) {
        if ($offset) {
            $separated .= ":" . substr($fingerprint, $offset, 4);
        } else {
            $separated = substr($fingerprint, $offset, 4);
        }
        $offset += 4;
    }
    return $separated;
}

1;
