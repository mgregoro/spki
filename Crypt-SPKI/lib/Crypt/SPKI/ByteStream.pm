#
# SocialPKI
# (c) Michael Gregorowicz 2014
#
# Encapsulation of bytestreams in an object

# ABSTRACT: Bytestream wrapper for ciphertexts, cleartexts, keys, hashes.

package Crypt::SPKI::ByteStream;
use strict;
use warnings;

use Crypt::Sodium;
use MIME::Base64 qw/encode_base64/;
use Mojo::Base 'Mojo::ByteStream';

sub crypto_hash_bytes {
    my ($self, $extra) = @_;
    
    my $to_hash = $self->to_string;
    if ($extra) {
        $to_hash .= $extra;
    }

    return __PACKAGE__->new(crypto_hash($to_hash));
}

sub crypto_hash_sum {
    my ($self, $extra) = @_;

    my $to_hash = $self->to_string;
    if ($extra) {
        $to_hash .= $extra;
    }

    return __PACKAGE__->new(unpack('H*', crypto_hash($to_hash)));
}

sub to_hex {
    my ($self, $extra) = @_;
    my $to_hash = $self->to_string;
    if ($extra) {
        $to_hash .= $extra;
    }
    return __PACKAGE__->new(unpack('H*', $to_hash));
}

sub from_hex {
    my ($self) = @_;
    my ($bytes, $string) = (undef, $self->to_string);
    if ($string =~ /^[0-9a-f]+$/io) {
        while ($string =~ /([0-9a-f]{2})/oig) {
            $bytes .= pack('H2', $1);
        }
    }
    return __PACKAGE__->new($bytes);
}

# a 64 byte wide base64 encoding
sub b64_encode {
    my ($self, $separator) = @_;
    my $e = encode_base64($self->to_string, '');

    $separator = "\n" unless defined $separator;

    # 64 byte chunks
    my $encoded;
    while ($e =~ /(.{1,64})/og) {
        $encoded .= "$1$separator";
    }

    return __PACKAGE__->new($encoded);
}

sub encrypt {
    my ($self, $pe, $se, $nonce) = @_;

    return __PACKAGE__->new(crypto_box($self->to_string, $nonce->to_string, $pe->to_string, $se->to_string));
}

sub decrypt {
    my ($self, $pe, $se, $nonce) = @_;

    return __PACKAGE__->new(crypto_box_open($self->to_string, $nonce->to_string, $pe->to_string, $se->to_string));
}

sub sign {
    my ($self, $msg) = @_;

    return __PACKAGE__->new(crypto_sign($msg, $self->to_string));
}

sub sign_digest {
    my ($self, $msg) = @_;

    return __PACKAGE__->new(crypto_sign(crypto_hash($msg), $self->to_string));
}

sub stream_xor {
    my ($self, $key, $nonce) = @_;

    return __PACKAGE__->new(crypto_stream_xor($self->to_string, $nonce->to_string, $key->to_string));
}

1;
