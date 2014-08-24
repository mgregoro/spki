#
# SocialPKI
# (c) Michael Gregorowicz 2014
#
# A class encapsulating an encrypted or signed message "CryptoGram"

package Crypt::SPKI::Crypto::Gram;
use strict;
use warnings;

use Mojo::Base -base;

use Carp qw/croak/;
use Crypt::Sodium;
use Crypt::SPKI::ByteStream;
use Crypt::SPKI::Util qw/cb_nonce/;
use Bencode qw/bencode bdecode/;

has payload => sub { undef };
has nonce => sub { undef };
has type => sub { 'cleartext' };
has signed_hash => sub { undef };
has signed_bytes => sub { undef };

has aa_header => '----- BEGIN SOCIALPKI CRYPTO GRAM -----';
has aa_footer => '----- END SOCIALPKI CRYPTO GRAM -----';

sub new {
    my ($class, $payload, $type, $nonce) = @_;

    unless ($payload && $type) {
        croak "Usage: Crypt::SPKI::Crypto::Gram->new(\$payload, \$type, \$nonce)\n";
    }

    unless (ref($payload) eq "Crypt::SPKI::ByteStream") {
        $payload = Crypt::SPKI::ByteStream->new($payload);
    }

    if ($nonce) {
        unless (ref($nonce) eq "Crypt::SPKI::ByteStream") {
            if (length($nonce) == crypto_box_NONCEBYTES) {
                $nonce = Crypt::SPKI::ByteStream->new($nonce);
            } else {
                # bogus nonce supplied, generating one.
                $nonce = cb_nonce();
            }
        }
    } else {
        # no nonce supplied, generating one.
        $nonce = cb_nonce();
    }

    return bless { payload => $payload, type => $type, nonce => $nonce }, $class;
}

sub from_string {
    my ($class, $aa) = @_;

    my $self = bless {}, $class;
    my @aa = split("\n", $aa);

    if (shift @aa eq $self->aa_header) {
        my $b64;
        while (my $line = shift @aa) {
            $b64 .= $line unless $line eq $self->aa_footer;
        }

        my $hr = bdecode(
            Crypt::SPKI::ByteStream->new($b64)->b64_decode->to_string
        );

        my $self = bless {
            payload => Crypt::SPKI::ByteStream->new($hr->{payload}),
            nonce => Crypt::SPKI::ByteStream->new($hr->{nonce}),
            type => $hr->{type},
        }, $class;

        if ($hr->{signed_hash}) {
            $self->{signed_hash} = $hr->{signed_hash};
        }

        if ($hr->{signed_bytes}) {
            $self->{signed_bytes} = $hr->{signed_bytes};
        }
        
        return $self;
    } else {
        croak "Ascii Armor block header does not match type $class\n";
    }
}

sub payload_string {
    my ($self) = @_;
    return $self->payload->to_string;
}

sub to_string {
    my ($self) = @_;
    my $hr = {
        nonce => $self->nonce->to_string,
        type => $self->type,
        payload => $self->payload_string,   
    };

    if (my $sh = $self->signed_hash) {
        $hr->{signed_hash} = $sh;
    }

    if (my $sb = $self->signed_bytes) {
        $hr->{signed_bytes} = $sb;
    }

    my @aa = ($self->aa_header . "\n");
    push(@aa, Crypt::SPKI::ByteStream->new( bencode($hr) )->b64_encode);
    push(@aa, $self->aa_footer . "\n");

    return join('', @aa);
}

1;
