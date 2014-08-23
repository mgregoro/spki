# Using the "Key" API 

```
# Generates a public + secret encryption key, and a public + secret signing key
my $keys = Crypt::SPKI::Keys->generate();

# sign some text...
my $signature = $keys->sign("Text");

# verify a signature...

```

