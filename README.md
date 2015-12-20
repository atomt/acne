# WARNING

*This is very experimental. Things still change around -a lot-*

# acne - a ACME/Let's Encrypt client

Acne is a ACME client that manages keys and certificates for you, but little else.

When certificates change it can call out to a set of hook scripts. These will usually just reload the needed daemons, but can also be used to install the certificates in other locations, invoke a configuration management system, or something else entirely.

It supports per certificate settings, like what CA, key parameters and what hooks to invoke, which will be preserved for automatic and manual renews. You could have some certificates issued from an internal PKI, and others from Let's Encrypt, for example, or using different accounts.

Some of this is working now; we have a working JWS + ACME client library, we can register accounts, submit domains for authorization, write out challenges and get cert + chain.

## Quick start

You probably want to install a couple of dependencies first. We try to keep dependencies down to what's available in distributions supported repositories.

For Ubuntu, Debian and their derivatives, the following should be sufficient

    sudo apt-get install libnet-ssleay-perl openssl

To install it from source, unpacked tarball or a git clone, run

    perl Build.PL
    ./Build
    sudo ./Build install
    sudo acne init

This will install it into `/usr/local` on most systems with configuration in `/etc/acne` and its internal certificate database in `/var/lib/acne`. `acne init` sets up the certificate database directory.

Currently only local file system based http-01 challenge is supported, so make sure your web server points `/.well-known/acme-challenge/` to the local directory `/var/lib/acne/httpchallenge` for all the virtual hosts you want to set up certificates for.

For nginx this would typically be a file like this, for example `/etc/nginx/acne.conf`

    location /.well-known/acme-challenge/ {
        default_type "text/plain";
        alias /var/lib/acne/httpchallenge/;
        try_files $uri =404;
    }

And in each server block include it like so

    server {
        ... other stuff ...
        include "/etc/nginx/acne.conf";
    }

The configuration file is loaded from `/etc/acne/config`. It will run fine without it, but its highly recommended to at least specify a contact email address for the default account as it is used for account recovery.

    account.default.email someone@example.com

See `/etc/acne/config.sample` for more options.

If everything is in order, you should be able to request a certificate, a -d for each domain name you want to include.

    sudo acne new example -d example.com -d www.example.com

And it should show up under `/var/lib/acne/live/example/` as `cert.pem`, `chain.pem`, `fullchain.pem` and `key.pem`. Then it's just a matter of pointing the service to the correct files.

Make your system run `acne renew-auto` on a daily or weekly basis. This will auto-renew certificates that are close to their expiry.

## Security

By default, acne runs as root, but it doesn't have to. It's usually best to create a dedicated system user and group for it, say called `acne`. Then just add the following to the configuration file

    system.user acne

Re-run acne init as root to update permissions on the certificate store

    sudo acne init

Then it's safe to invoke it as either root or this user directly. If invoked as root, it will automatically drop privileges to this user before doing anything else. This makes it convenient to just continue using it with sudo.

Your hook script(s) will have to take non-root operation into consideration for this to work smoothly.

## Basic usage

Create a new "example" entry in our store and get a certificate for name "example.com"

    acne new example -d example.com

This probably what you actually want, multiple names on a single certificate (SANs)

    acme new example -d example.com -d www.example.com

Use a non-default set of hooks (remembered for renew)

    acne new example -d example.com -d www.example.com --for nginx --for dovecot

Or use some other configured ACME enabled CA for this one certificate?

    acne new example -d example.com -d www.example.com --ca notletsencrypt

Renew all certificates in the store close to their expiry date, using same settings specified when created, including what hooks, CA and so on.

    acne renew-auto

Renew "example" certificate regardless of expiry date

    acne renew example

## Hooks

Hooks live in `/etc/acne/hooks/`, as one executable script or binary per hook (see defaults.for and --for). Hooks gets called with a parameter -- install, remove, postinst or postrm.

install is called once for each changed certificate, remove on each certificate removed. postinst is called after all installs have been processed and postrm likewise for removals.

A very simple hook for nginx would be saved to `/etc/acne/hooks/nginx` and look something like this

    #!/bin/sh -e
    case "$1" in
    install|remove|postrm)
        # Nothing to be done, we use certs directly from live/ in the cert store.
        exit 0
        ;;
    postinst)
        service nginx reload
        ;;
    esac

    exit 1

For install and remove the variables `name`, `cert`, `chain`, `fullchain` and `key` will be set. Except for name, they contain full paths to the respective files in the certificate store. They could be used to copy/remove and/or update server configuration, for example.

## Configuration
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
