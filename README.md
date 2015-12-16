# WARNING
*This is very experimental. It's currently not easily installable and is badly documented.*

# acne - a ACME/Let's Encrypt client
Acne is a ACME client that manages keys and certificates for you, but little else. When certificates change it will call out to a set of integration hook scripts. These would typically install the certs and reload the affected daemons. Or invoke some configuration management system.

It supports per certificate settings, like what CA, key parameters and what hooks to invoke, which will be preserved for automatic and manual renews. You could have some certificates issued from an internal PKI, and other from Let's Encrypt, for example.

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

Renew "acmetest" certificate regardless of expiry date
> acne renew acmetest

## Installation
Set up certificate store, default settings
> acne init

### Dependencies
Anything Unixy capable of running Perl 5.14 or later should work. This includes all currently supported platforms I know of.

#### Ubuntu 12.04+, Debian 7+
> apt-get install libjson-perl libnet-ssleay-perl openssl
