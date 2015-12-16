# acne
Experimental ACME client

Everyone and their dog is writing ACME/Lets Encrypt clients in all the
hip languages nowadays. So I'm going to write one in Perl. It's primarily
a learn myself ACME kind of project, but *could* turn into something
interesting.

It's targeted at Perl 5.14 and newer, with minimal amount of dependencies
outside of Perl core. Focus is currently on the core/protocol libraries.
Documentation is completely absent while the basics gets fleshed out.

Plan is to have something easily extendable with hooks in form of .d
directories with scripts, multiple CA/accounts and some smarts with
regards to rolling keys automatically on renews, remembering cert to CA
mappings and such.

Some of this is working now; we have a working JWS + ACME client library,
we can register accounts, submit domains for authorization, write out
challenges and get cert + chain.

## Basic usage

Create a new "acmetest" entry in our store and get a certificate for domain "acmetest.example.com"
> acne new acmetest -d acmetest.example.com

Multiple domains on a single certificate (SANs)
> acme new acmetest -d example.com -d www.example.com

Use a non-default set of hooks (calling out to say ansible also possible)
> acne new acmetest -d acmetest.example.com --for nginx --for dovecot

Or use some other ACME enabled CA for this one certificate?
> acne new acmetest -d acmetest.example.com --ca superawesomeacmeca

Renew all certificates in the store close to their expiry date, using same settings specified at new time
> acne renew-auto
