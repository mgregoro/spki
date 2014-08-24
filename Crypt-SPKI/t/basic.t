use strict;
use warnings;

use Test::More;

BEGIN { 
    use_ok('Crypt::SPKI');
    use_ok('Crypt::SPKI::Keys');
    use_ok('Crypt::SPKI::Keys::Public');
    use_ok('Crypt::SPKI::Keys::Secret');
    use_ok('Crypt::SPKI::ByteStream');
    use_ok('Crypt::SPKI::Crypto');
};

done_testing();

