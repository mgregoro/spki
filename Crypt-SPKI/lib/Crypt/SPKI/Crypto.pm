#
# SocialPKI
# (c) 2014 Michael Gregorowicz
#
# Class which encapsulates and simplifies interactions with Crypt::Sodium

package Crypt::SPKI::Crypto;

use Crypt::SPKI::Crypto::Gram;
use Crypt::SPKI::ByteStream;
use Crypt::SPKI::Util qw/cs_nonce cb_nonce/;
use Crypt::Sodium;

use strict;
use warnings;

sub new {
    my ($class) = @_;
    return bless {}, $class;
}

sub encrypt_gram {
    my ($self, $gram, $keys, $nonce) = @_;

    # convert raw strings to gram objects
    unless (ref($gram) eq "Crypt::SPKI::Crypto::Gram") {
        $gram = Crypt::SPKI::Crypto::Gram->new($gram, 'cleartext', $nonce);
    }

    my $e_gram = Crypt::SPKI::Crypto::Gram->new(
        $gram->payload->encrypt(
            $keys->{to}->public->enc,
            $keys->{from}->secret->enc,
            $gram->nonce,
        ), 'encrypted', $gram->nonce
    );

    return $e_gram;
}

sub decrypt_gram {
    my ($self, $e_gram, $keys, $nonce) = @_;

    # convert raw strings to gram objects
    unless (ref($e_gram) eq "Crypt::SPKI::Crypto::Gram") {
        $e_gram = Crypt::SPKI::Crypto::Gram->new($e_gram, 'encrypted', $nonce);
    }

    my $gram = Crypt::SPKI::Crypto::Gram->new(
        $e_gram->payload->decrypt(
            $keys->{from}->public->enc,
            $keys->{to}->secret->enc,
            $e_gram->nonce,
        ), 'cleartext', $e_gram->nonce
    );

    return $gram;
}


1;
