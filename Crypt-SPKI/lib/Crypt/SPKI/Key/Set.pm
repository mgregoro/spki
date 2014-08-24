#
# SocialPKI
# (c) Michael Gregorowicz 2014
#
# A base class for SPKI Key Sets

# ABSTRACT: SocialPKI key set base class

package Crypt::SPKI::Key::Set;
use strict;
use warnings;

use Mojo::Base -base;
use Bencode qw/bdecode bencode/;
use Carp qw/croak/;
use Crypt::SPKI::ByteStream;

has enc => sub { undef };
has sign => sub { undef };
has extra => sub { {} };

sub new {
    my ($class, $options) = @_;
    return bless {
        enc => "$class\::Enc"->new($options->{enc}),
        sign => "$class\::Sign"->new($options->{sign}),
        extra => $options->{extra} ? $options->{extra} : {},
    }, $class; 
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

        $self->{enc} = "$class\::Enc"->new($hr->{$class}->{enc});
        $self->{sign} = "$class\::Sign"->new($hr->{$class}->{sign});
        $self->{extra} = $hr->{$class}->{extra} ? $hr->{$class}->{extra} : {};

        return $self;
    } else {
        croak "Ascii Armor block does not match type $class\n";
    }
}

sub to_string {
    my ($self, $extra) = @_;

    # build the ascii armor
    my @aa;
    push(@aa, $self->aa_header . "\n");
    my $hr = {        
        ref($self) => {
            sign => $self->sign->to_hex->to_string,
            enc => $self->enc->to_hex->to_string,
        },
    };

    if ($extra) {
        $hr->{ref($self)}->{extra} = $extra;
    }

    push(@aa, Crypt::SPKI::ByteStream->new( bencode($hr) )->b64_encode);
    push(@aa, $self->aa_footer . "\n");

    return join('', @aa);
}

sub fingerprint {
    return undef;
}



1;
