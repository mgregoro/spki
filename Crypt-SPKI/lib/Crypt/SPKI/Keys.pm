#
# SocialPKI
# (c) Michael Gregorowicz 2014
#
# A base class for Crypt::SPKI key pairs!

# ABSTRACT: Encapsulating class for a pair of keysets; referred to as a "keypair".

use strict;
use warnings;
package Crypt::SPKI::Keys;
use Mojo::Base -base;

use Carp qw/croak/;
use Crypt::Sodium;
use Bencode qw/bdecode bencode/;
use Crypt::SPKI::ByteStream;
use Crypt::SPKI::Keys::Public;
use Crypt::SPKI::Keys::Secret;

has aa_header => '----- BEGIN SOCIALPKI KEYPAIR -----';
has aa_footer => '----- END SOCIALPKI KEYPAIR -----';

# this generates a new keypair!
sub new {
    my ($class) = @_;

    my ($enc_public, $enc_secret)  = map { unpack('H*', $_) } box_keypair();
    my ($sign_public, $sign_secret) = map { unpack('H*', $_) } sign_keypair();

    my $self = bless {}, $class;

    $self->{"Crypt::SPKI::Keys::Public"} = Crypt::SPKI::Keys::Public->new({
        enc => $enc_public,
        sign => $sign_public,
    });

    $self->{"Crypt::SPKI::Keys::Secret"} = Crypt::SPKI::Keys::Secret->new({
        enc => $enc_secret,
        sign => $sign_secret,
    });

    return $self;
}

# must be instantiated with an ascii armor block.
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
 
        foreach my $type (keys %$hr) {
            $self->{$type} = $type->new($hr->{$type});
        }
        return $self;
    } else {
        croak "Ascii Armor block header does not match type $class\n";
    }
}

sub to_string {
    my ($self, $extra) = @_;

    # build the ascii armor
    my @aa;
    push(@aa, $self->aa_header . "\n");
    
    # merge the two structures
    my $hr = {};
    foreach my $type (qw/Crypt::SPKI::Keys::Public Crypt::SPKI::Keys::Secret/) {
        $hr->{$type} = {
            enc => $self->{$type}->{enc}->to_hex->to_string,
            sign => $self->{$type}->{sign}->to_hex->to_string,
        };
        if ($extra) {
            $hr->{$type}->{extra} = $extra;
        }
    }

    push(@aa, Crypt::SPKI::ByteStream->new( bencode($hr) )->b64_encode);
    push(@aa, $self->aa_footer . "\n");

    return join('', @aa);
}

sub public {
    my ($self) = @_;
    return $self->{"Crypt::SPKI::Keys::Public"};
}

sub secret {
    my ($self) = @_;
    return $self->{"Crypt::SPKI::Keys::Secret"};
}


1;
