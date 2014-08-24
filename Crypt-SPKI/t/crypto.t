use strict;
use warnings;

use Test::More;

use Crypt::SPKI::Keys;
use Crypt::SPKI::Crypto;
use Crypt::SPKI::Crypto::Gram;

# introducing Alice and Bob!
my $alice = Crypt::SPKI::Keys->new();
my $bob = Crypt::SPKI::Keys->new();

my $crypto = Crypt::SPKI::Crypto->new();

my $cleartext = "The quick brown fox jumped over the lazy dog";
my $e_gram = $crypto->encrypt_gram(
    $cleartext, {
        from => $alice, 
        to => $bob,
    }
);

is(ref($e_gram), 'Crypt::SPKI::Crypto::Gram', "Making sure our ciphertext is a Crypto::Gram object");
is($e_gram->type, 'encrypted', "Making sure gram has type 'encrypted'");

my $gram = $crypto->decrypt_gram(
    $e_gram, {
        from => $alice,
        to => $bob,
    },
);

is($gram->payload_string, $cleartext, "Checking decryption from Script::SPKI::Crypto::Gram object");

$gram = $crypto->decrypt_gram(
    $e_gram->payload->to_string, {
        from => $alice,
        to => $bob,
    }, $e_gram->nonce
);

is($gram->payload_string, $cleartext, "Checking decryption from string");

my $g_string = $e_gram->to_string;
$e_gram = Crypt::SPKI::Crypto::Gram->from_string($g_string);

$gram = $crypto->decrypt_gram(
    $e_gram->payload->to_string, {
        from => $alice,
        to => $bob,
    }, $e_gram->nonce
);

is($gram->payload_string, $cleartext, "Checking decryption from serialized/deserialized Crypto::Gram object");

done_testing();