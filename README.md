# acne
Experimental ACME client

Everyone and their dog is writing ACME/Lets Encrypt clients in all the
hip languages nowadays. But I'm not seeing anything in Perl! So I'm
going to fix that..

OK, mostly it is for me to learn how ACME works, but it might become
something interesting.

Focus is currently on the core/protocol libraries.
Documentation is completely absent while the basics gets fleshed out.

Plan is to have something easily extendable with hooks in form of .d
directories with scripts, multiple CA/accounts and some smarts with
regards to rolling keys automatically on renews and such.