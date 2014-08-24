use strict;
use warnings;

use Test::More;

use Crypt::SPKI::Keys;
use Crypt::SPKI::Keys::Public;
use Crypt::SPKI::Keys::Secret;

my $keys = Crypt::SPKI::Keys->new();

is(ref($keys), "Crypt::SPKI::Keys", "Key generation test");

# test round trip
my $aa = $keys->to_string;
$keys = Crypt::SPKI::Keys->from_string($aa);

is($aa, $keys->to_string, "Testing Ascii Armor round trip; key loading");

my $pub_aa = $keys->public->to_string;
my $pk = Crypt::SPKI::Keys::Public->from_string($pub_aa);

is($pk->to_string, $keys->public->to_string, "Sanity checking keypair and public keyset Ascii Armor generators against eachother");
is($pub_aa, $pk->to_string, "Testing public keyset Ascii Armor round trip; keyset loading");

my $sec_aa = $keys->secret->to_string;
my $sk = Crypt::SPKI::Keys::Secret->from_string($sec_aa);

is ($sk->to_string, $keys->secret->to_string, "Sanity checking keypair and secret keyset Ascii Armor generators against eachother");
is($sec_aa, $sk->to_string, "Testing secret keyset Ascii Armor round trip; keyset loading");

done_testing();

