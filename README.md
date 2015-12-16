# acne
Experimental ACME client

Everyone and their dog is writing ACME/Lets Encrypt clients in all the hip languages nowadays. So I'm going to write one in Perl. It's targeted at Perl 5.14 and newer, with minimal amount of dependencies outside of Perl core. Focus is currently on the core/protocol libraries. Documentation is mostly absent while the basics gets fleshed out.

Plan is to have something easily extendable with hooks in form of .d directories with scripts, multiple CA/accounts and some smarts with regards to rolling keys automatically on renews, remembering cert to CA/hooks mappings and such. Acne itself will only manage certificates and keys, user supplied hook scripts will be responsible for installing certificates and reloading daemons.

Some of this is working now; we have a working JWS + ACME client library, we can register accounts, submit domains for authorization, write out challenges and get cert + chain.

## Basic usage

Create a new "acmetest" entry in our store and get a certificate for domain "acmetest.example.com"
> acne new acmetest -d acmetest.example.com

Multiple domains on a single certificate (SANs)
> acme new acmetest -d example.com -d www.example.com

Use a non-default set of hooks (calling out to say ansible also possible, also used on renew)
> acne new acmetest -d acmetest.example.com --for nginx --for dovecot

Or use some other ACME enabled CA for this one certificate?
> acne new acmetest -d acmetest.example.com --ca superawesomeacmeca

Renew all certificates in the store close to their expiry date, using same settings specified when created, including what hooks, CA and so on.
> acne renew-auto

Renew a "acmetest" certificate regardless of expiry date
> acne renew acmetest

## Installation
Set up certificate store, default settings
> acne init

### Dependencies
#### Ubuntu 12.04+, Debian 7+
> apt-get install libjson-perl libnet-ssleay-perl openssl
