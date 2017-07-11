-module(rpcaller_digest).

-export([verify/2]).
-export([generate/1]).
-export([encode/1]).
-export([decode/1]).

-type value() :: {sha256, string()}.
-export_type([value/0]).

verify(Data, {sha256, _Hash} = Digest) ->
    generate(Data) =:= Digest.

generate(Data) ->
    {sha256, base64:encode_to_string(crypto:hash(sha256, Data))}.

encode({sha256, Hash}) ->
    "SHA-256=" ++ Hash.

decode(EncodedDigest) ->
    case rpcaller_util:string_tokens_n(EncodedDigest, "=", 2) of
        [DigestType, DigestValue] ->
            case string:to_upper(DigestType) of
                "SHA-256" -> {ok, {sha256, DigestValue}};
                _ -> error
            end;
        _ ->
            error
    end.
