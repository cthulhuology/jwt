jwt.erl - simple jwt lib for erlang
===================================

This is a pretty minimal single beam erlang module

Usage
------

To build I use https://github.com/cthulhuology/beamer

	beamer make

You can also make an rsa keypair with if you have openssl installed:
	openssl genrsa -out private.pem 2048
	openssl rsa -in private.pem -outform PEM -pubout -out public.pem

You can sign some claims:

	{ ok, PrivateKey } = file:read_file("private.key"),
	JWT = jwt:sign(rs256, [ { <<"sub">>, <<"1234">> }, 
		{ <<"iat">>, 1516239022 }, { <<"name">>, <<"JD">> }], PrivateKey).

You can extract the claims (if valid with:

	{ ok, PublicKey } = file:read_file("public.key"),
	Claims = jwt:claims(JWT,PublicKey).

If the claims are invalid (or parsing fails) the value of Claims would be invalid.



