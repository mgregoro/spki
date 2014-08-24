#
# SocialPKI
# (c) Michael Gregorowicz 2014
#
# (S)implified (o)ntological (c)ryptography (i)n (a) (l)ibrary

use strict;
use warnings;
package Crypt::SPKI;

# ABSTRACT: SocialPKI: Simplified identity cryptography for a decentralized web

=pod

=head1 OVERVIEW
    
Crypt::SPKI (SocialPKI) is an attempt to simplify cryptographic primitives that provide the following:

=for :list
* Proof of Identity/Origin (secret key ownership)
* Third Party Assertion of "Truths"
* First Party Publication of "Truths"
* First Party Authorization of Data Access
* Web of Trust (public key signing)
* Foundations for a distributed Social Network and a Worldwide ERP-like system
* A Personal PKI / CA hierarchy with a master key and several layers of verifiable / chainable proxy keys
=end :list

=cut

1;
