%% jwk
%%
%% MIT No Attribution  
%% Copyright 2023 David J Goehrig <dave@dloh.org>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy 
%% of this software and associated documentation files (the "Software"), to 
%% deal in the Software without restriction, including without limitation the 
%% rights to use, copy, modify, merge, publish, distribute, sublicense, and/or 
%% sell copies of the Software, and to permit persons to whom the Software is 
%% furnished to do so.  
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
%% IN THE SOFTWARE.


%%
%% depends on json module
%%

-module(jwk).
-author({ "David J Goehrig", "dave@dloh.org"}).
-copyright(<<"© 2023 David J. Goehrig"/utf8>>).
-export([ keypair/1, public/2, private/2 ]).

-include_lib("public_key/include/public_key.hrl").

public_encoding(Id,Key) ->
	Modulus = list_to_binary(jwt:b64encode(binary:encode_unsigned(Key#'RSAPublicKey'.modulus))),
	Exponent =  list_to_binary(jwt:b64encode(binary:encode_unsigned(Key#'RSAPublicKey'.publicExponent))),
	json:encode([{<<"kty">>,<<"RSA">>},{<<"n">>, Modulus }, {<<"e">>, Exponent},
		{<<"alg">>,<<"RS256">>},{<<"kid">>,Id},{<<"use">>,<<"sig">>}]).

private_encoding(Id,Key) ->
	json:encode([{<<"kty">>,<<"RSA">>},{<<"n">>, jwt:b64encode(binary:encode_unsigned(Key#'RSAPrivateKey'.modulus))},
		{<<"e">>,jwt:b64encode(binary:encode_unsigned(Key#'RSAPrivateKey'.publicExponent))},{<<"alg">>,<<"RS256">>},
		{<<"kid">>,Id},{<<"use">>,<<"sig">>}]).

keypair(Id) ->
	Key = public_key:generate_key({rsa,2048,65537}),
	Public = public_encoding(Id,#'RSAPublicKey'{ modulus= Key#'RSAPrivateKey'.modulus, publicExponent = Key#'RSAPrivateKey'.publicExponent}),
	Private = private_encoding(Id,Key),
	{ Private, Public }.

	
public(Id,Filename) ->
	{ok,File} = file:read_file(Filename),
	[Data] = public_key:pem_decode(File),
	Key = public_key:pem_entry_decode(Data),
	public_encoding(Id,Key).
	

private(Id,Filename) ->
	{ok,File} = file:read_file(Filename),
	[Data] = public_key:pem_decode(File),
	Key = public_key:pem_entry_decode(Data),
	private_encoding(Id,Key).

