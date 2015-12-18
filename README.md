# WARNING
*This is very experimental. It's currently not easily installable and is badly documented. If you dont guess the correct configuration, it will fail in mysterious ways*

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

## Configuration
The configuration file is loaded from /etc/acne/config by default. It is a simple key value file. A minimal configuration would look like this, to set up our certificate/key store and the webserver challenge root.

    system.store /var/lib/acne
    challenge.http01fs.acmeroot /srv/web/shared/acme

You probably want to define a contact email for account recovery and such, though.

    account.default.email someone@example.com

It's also highly recomended to create a dedicated user for acne, otherwise it will run as root. Hooks will need to keep non-root operation in mind, though.

    system.user acne
    
And to use the non-testing production Let's Encrypt by default (can be overidden with --ca on new)

    defaults.ca letsencrypt

Full example

    system.store  /var/lib/acne
    system.user   root
    
    account.default.email someone@example.com
    account.default.tel   776-2323
    
    defaults.account    default
    defaults.ca         letsencrypt-staging
    defaults.renew-left 10
    defaults.roll-key   yes
    defaults.key        rsa:3072
    defaults.for        space delimeted sets of hooks
    
    challenge.http01fs.acmeroot /srv/web/shared/acme
    
    ca.internal.host acme-v1.api.example.com

## Installation
Set up certificate store, default settings
> acne init

### Dependencies
Anything Unixy capable of running Perl 5.14 or later should work. This includes all currently supported platforms I know of.

#### Ubuntu 12.04+, Debian 7+
> apt-get install libjson-perl libnet-ssleay-perl openssl
