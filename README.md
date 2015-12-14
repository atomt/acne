# acne
Experimental ACME client

Everyone and their dog is writing ACME/Lets Encrypt clients in all the
hip languages nowadays. But I'm not seeing anything in Perl! So I'm
going to fix that.. OK, so mostly it is for me to learn how ACME works,
but it might become something interesting.

It's targeted at Perl 5.14 and newer, with minimal amount of dependencies
outside of Perl core. Currenly only JSON and a openssl binary should be
required. Worst case, "apt-get install libjson-perl openssl" should be
sufficient to get going on Debian-like Linux distributions.

Focus is currently on the core/protocol libraries.
Documentation is completely absent while the basics gets fleshed out.

Plan is to have something easily extendable with hooks in form of .d
directories with scripts, multiple CA/accounts and some smarts with
regards to rolling keys automatically on renews and such.

Some of this is working now; we have a working JWS + ACME client library,
we can register accounts, submit domains for authorization and write out
challenges.