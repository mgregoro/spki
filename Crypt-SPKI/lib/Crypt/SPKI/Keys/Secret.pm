#
# SocialPKI
# (c) 2014 Michael Gregorowicz
#
# Class which contains both Encryption and Signing Secret Keys
#

# ABSTRACT: Key set class encapsulating a secret encryption key, and a secret signing key

package Crypt::SPKI::Keys::Secret;
use warnings;
use strict;

use Mojo::Base 'Crypt::SPKI::Key::Set';

use Crypt::SPKI::Keys::Secret::Enc;
use Crypt::SPKI::Keys::Secret::Sign;

has aa_header => '----- BEGIN SOCIALPKI SECRET KEY -----';
has aa_footer => '----- END SOCIALPKI SECRET KEY -----';



1;
