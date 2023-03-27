%% jwt
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

-module(jwt).
-author({ "David J Goehrig", "dave@dloh.org"}).
-copyright(<<"© 2023 David J. Goehrig"/utf8>>).
-export([ 
	hs256_header/0, 
	rs256_header/0,
	depad/1, pad/1,
	b64encode/1, b64decode/1, 
	payload_sample/0,
	sign/3, claims/2 
	]).

%% depad removes = trailing b64 encoded
depad(T) when is_binary(T) ->
	depad(lists:reverse(binary_to_list(T)));
depad([$=|T]) ->
	depad(T);
depad(T) ->
	lists:reverse(T).

%% pad adds trailing = 
pad(Buffer) ->
	case byte_size(Buffer) rem 4 of
		2 -> <<Buffer/binary, "==">>;
		3 -> <<Buffer/binary, "=">>;
		_ -> Buffer
	end.

%% url decode special chars
decode_char($_) -> $/;
decode_char($-) -> $+;
decode_char(X) -> X.


%% base64 url decode
b64decode(Buffer) ->
	base64:decode(pad(<< << (decode_char(C)) >> || <<C>> <= Buffer >>)).

%% url encode special chars
encode_char($/) -> $_;
encode_char($+) -> $-;
encode_char(X) -> X.

%% base64 url decode
b64encode(Buffer) ->
	depad(<< << (encode_char(C)) >> || <<C>> <= base64:encode(Buffer) >>).

%% { "alg": "HS256", "typ": "JWT" }
hs256_header() ->
	b64encode(json:encode([ { <<"alg">>, <<"HS256">>}, { <<"typ">>, <<"JWT">> } ])).

%% { "alg":"RS256", "typ":"JWT" } 
rs256_header() ->
	b64encode(json:encode([ { <<"alg">>, <<"RS256">> }, { <<"typ">>, <<"JWT">> } ])). 

%% { "sub": "1234567890", "name": "John Doe", "iat": 1516239022 }
payload_sample() ->
	json:encode([ { <<"sub">>, <<"1234567890">> }, { <<"name">>, <<"John Doe">> }, { <<"iat">>, 1516239022 } ]).

%% Select one of the two supported algos
algo(<<"RS256">>) -> rs256;
algo(<<"HS256">>) -> hs256;
algo(_) -> unsupported.

%% Fetch claims or invalid
claims(rs256,Claims,Payload,Signature,Key) ->
	[Data] = public_key:pem_decode(Key),
	PublicKey = public_key:pem_entry_decode(Data),
	case public_key:verify(Payload,sha256,Signature,PublicKey) of
		true -> 
			json:decode(b64decode(Claims));
		_ ->
			invalid
	end;		

claims(hs256,Claims,Payload,Signature,Key) ->
	case Signature =:= crypto:mac(hmac,sha256, Key, Payload) of
		true ->
			json:decode(b64decode(Claims));	
		_ ->
			invalid
	end;

claims(_,_,_,_,_) ->
	invalid.

claims(Jwt,Key) when is_list(Jwt) ->
	claims(list_to_binary(Jwt),Key);
claims(Jwt,Key)->
	[ Header, Claims, Signature ] = binary:split(Jwt,<<".">>,[global]),
	Payload = << Header/binary, $., Claims/binary >>,
	Headers = json:decode(b64decode(Header)),
	Algo = algo(proplists:get_value(<<"alg">>,Headers)),
	claims(Algo,Claims,Payload,b64decode(Signature), Key).

%% HS256 signing
hs256_sign(Payload,Secret) ->
	b64encode(crypto:mac(hmac,sha256, Secret,Payload)).

%% RS256 signing
rs256_sign(Payload,PrivatePem) ->
	[Data] = public_key:pem_decode(PrivatePem),
	PrivateKey = public_key:pem_entry_decode(Data),
	b64encode(public_key:sign(Payload,sha256,PrivateKey)).

%%  Create JWTs
sign(hs256, Claims,Secret) ->
	SigningString = hs256_header() ++ "." ++ b64encode(json:encode(Claims)),
	SigningString ++ "." ++ hs256_sign(SigningString,Secret);

sign(rs256, Claims,PrivatePem) ->
	SigningString = rs256_header() ++ "." ++ b64encode(json:encode(Claims)),
	SigningString ++ "." ++ rs256_sign(SigningString,PrivatePem);

sign(_, _, _) -> 
	io:format("Unsupported algo~n").

