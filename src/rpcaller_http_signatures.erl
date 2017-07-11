-module(rpcaller_http_signatures).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([create_authorized_request/6]).
-export([encode_authorized_request_headers/1]).
-export([decode_authorized_request/3]).
-export([verify_authorized_request/2]).

-export([create_authorized_response/4]).
-export([encode_authorized_response_headers/1]).
-export([decode_authorized_response/1]).
-export([verify_authorized_response/3]).

% list taken from: https://ninenines.eu/docs/en/cowboy/1.0/manual/cowboy_req/#decode_header
-define(MANDATORILY_SIGNED_HEADER_NAMES,
        ["accept",
         "accept-charset",
         "accept-encoding",
         "accept-language",
         %"authorization",
         "content-length",
         "content-type",
         "cookie",
         "date",
         "expect",
         "if-match",
         "if-modified-since",
         "if-none-match",
         "if-unmodified-since",
         "range",
         "sec-websocket-protocol",
         "transfer-encoding",
         "upgrade"
         %"x-forwarded-for"
         ]).

%-define(ALGORITHM, "hmac-sha256"). % nothing else supported for now

%
% https://tools.ietf.org/html/draft-cavage-http-signatures-06
%

-type authorization() ::
    #{ key_id := binary(), % username
       algorithm := binary(), % TODO
       signed_header_names := [binary()], % including pseudo
       signature := binary() }.

-type authorized_request() ::
    #{ authorization := authorization(),
       method := string(),
       hostless_uri := string(), % wit
       signed_headers := [header()],
       unsigned_headers := [header()],
       body_digest := rpcaller_digest:value() }.

-type authorized_response() ::
    #{ authorization := authorization(),
       signed_headers := [header()],
       unsigned_headers := [header()],
       body_digest := rpcaller_digest:value() }.

-type header() :: {Name :: string(), Value :: string() | authorization() | rpcaller_digest:value()}.


create_authorized_request(KeyId, SigningParams, Method, HostlessURI, Headers, Body) ->
    % body digest
    BodyDigest = rpcaller_digest:generate(Body),

    % signature
    {SignatureString, SignedHeaderNames, SignedHeaders} =
        create_request_signature_string(Method, HostlessURI, Headers, BodyDigest),
    {Algorithm, Signature} = sign(SigningParams, SignatureString),
    %io:format("~ncreating signature string ~p~n", [SignatureString]),

    % authorization
    Authorization =
        #{ key_id => KeyId, % username
           algorithm => Algorithm,
           signed_header_names => SignedHeaderNames,
           signature => Signature },
    AuthorizationHeader =
        {"authorization", Authorization},

    #{ authorization => Authorization,
       method => Method,
       hostless_uri => HostlessURI,
       signed_headers => SignedHeaders,
       unsigned_headers => [AuthorizationHeader],
       body_digest => BodyDigest }.

encode_authorized_request_headers(AuthorizedRequest) ->
    #{ signed_headers := SignedHeaders,
       unsigned_headers := UnsignedHeaders } = AuthorizedRequest,
    encode_headers(SignedHeaders ++ UnsignedHeaders).


decode_authorized_request(Method, HostlessURI, Headers) ->
    decode_authorized_request_(Method, HostlessURI, decode_headers(Headers)).

decode_authorized_request_(_Method, _HostlessURI, {error, HeaderParsingError}) ->
    {error, {headers, HeaderParsingError}};
decode_authorized_request_(Method, HostlessURI, {ok, DecodedHeaders}) ->
    case kvlists_find("authorization", DecodedHeaders) of
        {ok, Authorization} ->
            #{ signed_header_names := SignedHeaderNames } = Authorization,

            % we have to make sure SignedHeaders is in the same order as SignedHeaderNames
            {SignedHeaders, UnsignedHeaders} =
                lists:foldr(
                  fun (SignedHeaderName, {SignedHeadersAcc, UnsignedHeadersAcc}) ->
                          {Taken, Remaining} =
                            kvlists_take_all_with(
                              fun (HeaderName) -> HeaderName =:= SignedHeaderName end,
                              UnsignedHeadersAcc),
                          {Taken ++ SignedHeadersAcc, Remaining}
                  end,
                  {[], DecodedHeaders},
                  SignedHeaderNames),

            BodyDigest = kvlists_fetch("digest", SignedHeaders),
            AuthorizedRequest =
                #{ authorization => Authorization, % TODO avoid duplicate authorization params in UnsignedHeaders?
                   method => Method,
                   hostless_uri => HostlessURI,
                   signed_headers => SignedHeaders,
                   unsigned_headers => UnsignedHeaders,
                   body_digest => BodyDigest },
            {ok, AuthorizedRequest};
        error ->
            {error, authorization_header_missing}
    end.


verify_authorized_request(AuthorizedRequest, SigningParams) ->
    #{ authorization := Authorization,
       method := Method,
       hostless_uri := HostlessURI,
       signed_headers := SignedHeaders,
       unsigned_headers := UnsignedHeaders,
       body_digest := BodyDigest } = AuthorizedRequest,
    (not lists:any(fun is_mandatorily_signed_header/1, UnsignedHeaders)
     andalso
     begin
         #{ algorithm := RequestAlgorithm,
            signature := RequestSignature } = Authorization,
         SignatureString = reconstruct_request_signature_string(Method, HostlessURI, SignedHeaders),
         %io:format("~nreconstrucing signature string ~p~n", [SignatureString]),
         {Algorithm, Signature} = sign(SigningParams, SignatureString),
         (Algorithm =:= RequestAlgorithm
          andalso Signature =:= RequestSignature
          andalso {true, BodyDigest})
     end).




create_authorized_response(KeyId, SigningParams, Headers, Body) ->
    % body digest
    BodyDigest = rpcaller_digest:generate(Body),

    % signature
    {SignatureString, SignedHeaderNames, SignedHeaders} =
        create_response_signature_string(Headers, BodyDigest),
    {Algorithm, Signature} = sign(SigningParams, SignatureString),
    %io:format("~ncreating signature string ~p~n", [SignatureString]),

    % authorization
    Authorization =
        #{ key_id => KeyId, % username
           algorithm => Algorithm,
           signed_header_names => SignedHeaderNames,
           signature => Signature },

    % signature
    SignatureHeader =
        {"signature", Authorization},

    #{ authorization => Authorization,
       signed_headers => SignedHeaders,
       unsigned_headers => [SignatureHeader],
       body_digest => BodyDigest }.

encode_authorized_response_headers(AuthorizedResponse) ->
    #{ signed_headers := SignedHeaders,
       unsigned_headers := UnsignedHeaders } = AuthorizedResponse,
    io:format("encoding response headers: ~p~n", [{SignedHeaders, UnsignedHeaders}]),
    encode_headers(SignedHeaders ++ UnsignedHeaders).

decode_authorized_response(Headers) ->
    decode_authorized_response_(decode_headers(Headers)).

decode_authorized_response_({error, HeaderParsingError}) ->
    {error, {headers, HeaderParsingError}};
decode_authorized_response_({ok, DecodedHeaders}) ->
    case kvlists_find("signature", DecodedHeaders) of
        % TODO de-duplicate code common with decode_authorized_request_
        {ok, Authorization} ->
            #{ signed_header_names := SignedHeaderNames } = Authorization,

            % we have to make sure SignedHeaders is in the same order as SignedHeaderNames
            {SignedHeaders, UnsignedHeaders} =
                lists:foldr(
                  fun (SignedHeaderName, {SignedHeadersAcc, UnsignedHeadersAcc}) ->
                          {Taken, Remaining} =
                            kvlists_take_all_with(
                              fun (HeaderName) -> HeaderName =:= SignedHeaderName end,
                              UnsignedHeadersAcc),
                          {Taken ++ SignedHeadersAcc, Remaining}
                  end,
                  {[], DecodedHeaders},
                  SignedHeaderNames),

            io:format("decoded response headers: ~p~n", [{SignedHeaders, UnsignedHeaders}]),
            BodyDigest = kvlists_fetch("digest", SignedHeaders),
            AuthorizedResponse =
                #{ authorization => Authorization, % TODO avoid duplicate authorization params in UnsignedHeaders?
                   signed_headers => SignedHeaders,
                   unsigned_headers => UnsignedHeaders,
                   body_digest => BodyDigest },
            {ok, AuthorizedResponse};
        error ->
            {error, signature_header_missing}
    end.

verify_authorized_response(AuthorizedResponse, KeyId, SigningParams) ->
    % TODO remove duplicate code common with verify_authorized_request
    #{ authorization := Authorization,
       signed_headers := SignedHeaders,
       unsigned_headers := UnsignedHeaders,
       body_digest := BodyDigest } = AuthorizedResponse,
    (not lists:any(fun is_mandatorily_signed_header/1, UnsignedHeaders)
     andalso
     begin
         #{ key_id := ResponseKeyId,
            algorithm := ResponseAlgorithm,
            signature := ResponseSignature } = Authorization,
         SignatureString = reconstruct_response_signature_string(SignedHeaders),
         %io:format("~nreconstrucing signature string ~p~n", [SignatureString]),
         {Algorithm, Signature} = sign(SigningParams, SignatureString),
         (KeyId =:= ResponseKeyId
          andalso Algorithm =:= ResponseAlgorithm
          andalso Signature =:= ResponseSignature
          andalso {true, BodyDigest})
     end).


encode_headers(Headers) ->
    encode_headers_recur(Headers, []).

encode_headers_recur([{K,V} | T], Acc) ->
    LowK = string:to_lower(K),
    encode_headers_recur(T, [{K, encode_header(LowK, V)} | Acc]);
encode_headers_recur([], Acc) ->
    lists:reverse(Acc).

encode_header("authorization", Authorization) ->
    % authorization header
    #{ key_id := KeyId,
       algorithm := Algorithm,
       signed_header_names := SignedHeaderNames,
       signature := Signature } = Authorization,

    "signature " ++
    encode_authorization_signature_params(
      [{"keyId", KeyId},
       {"algorithm", Algorithm},
       {"headers", encode_signed_header_names(SignedHeaderNames)},
       {"signature", Signature}]);
encode_header("digest", Value) ->
    rpcaller_digest:encode(Value);
encode_header("signature", Authorization) ->
    % signature header
    % TODO remove duplicate code (compare with 'authorization' encoding)
    #{ key_id := KeyId,
       algorithm := Algorithm,
       signed_header_names := SignedHeaderNames,
       signature := Signature } = Authorization,
    encode_authorization_signature_params(
      [{"keyId", KeyId},
       {"algorithm", Algorithm},
       {"headers", encode_signed_header_names(SignedHeaderNames)},
       {"signature", Signature}]);
encode_header(_Name, Value) ->
    Value.


decode_headers(Headers) ->
    decode_headers_recur(Headers, []).

decode_headers_recur([{K,V} | T], Acc) ->
    LowK = string:to_lower(K),
    case decode_header(LowK, V) of
        {ok, DecodedV} -> decode_headers_recur(T, [{LowK,DecodedV} | Acc]);
        {error, Error} -> {error, {K,Error}};
        error -> {error, K}
    end;
decode_headers_recur([], Acc) ->
    {ok, lists:reverse(Acc)}.

decode_header("authorization", Value) ->
    case rpcaller_util:string_tokens_n(Value, " ", 2) of
        [Type, EncodedParams] ->
            case string:to_lower(Type) of
                "signature" ->
                    % TODO parsing errors below
                    Params = decode_authorization_signature_params(EncodedParams),
                    KeyId = kvlists_fetch("keyId", Params),
                    AlgorithmType = kvlists_fetch("algorithm", Params),
                    SignedHeaderNames = decode_signed_header_names( kvlists_fetch("headers", Params) ),
                    Signature = kvlists_fetch("signature", Params),

                    {ok,
                     #{ key_id => KeyId,
                        algorithm => AlgorithmType,
                        signed_header_names => SignedHeaderNames,
                        signature => Signature }};
                _ ->
                    {error, invalid_auth_type}
            end;
        _ ->
            {error, wrong_number_of_tokens}
    end;
decode_header("signature", Value) ->
    % TODO parsing errors below
    Params = decode_authorization_signature_params(Value),
    KeyId = kvlists_fetch("keyId", Params),
    AlgorithmType = kvlists_fetch("algorithm", Params),
    SignedHeaderNames = decode_signed_header_names( kvlists_fetch("headers", Params) ),
    Signature = kvlists_fetch("signature", Params),
    {ok,
     #{ key_id => KeyId,
        algorithm => AlgorithmType,
        signed_header_names => SignedHeaderNames,
        signature => Signature }};
decode_header("digest", Value) ->
    rpcaller_digest:decode(Value);
decode_header(_Name, Value) ->
    {ok, Value}.

create_request_signature_string(RequestMethod, RequestURI, RequestHeaders, BodyDigest) ->
    PseudoHeaders = request_target_pseudo_headers(RequestMethod, RequestURI),
    create_signature_string(PseudoHeaders, RequestHeaders, BodyDigest).

create_response_signature_string(ResponseHeaders, BodyDigest) ->
    create_signature_string([], ResponseHeaders, BodyDigest).

create_signature_string(PseudoHeaders, Headers, BodyDigest) ->
    WithBodyDigest = Headers ++ [{"digest", BodyDigest}],
    WithPseudo = PseudoHeaders ++ WithBodyDigest,
    WithLowercasedNames =
        lists:keymap(fun string:to_lower/1, 1, WithPseudo),
    UniqueHeaderNames =
        map_unique(fun ({Name, _Value}) -> Name end, WithLowercasedNames),
    Lines =
        lists:map(
          fun (HeaderName) ->
                  HeaderValues = proplists:get_all_values(HeaderName, WithLowercasedNames),
                  EncodedHeaderValues =
                    [encode_header(HeaderName, HeaderValue)
                     || HeaderValue <- HeaderValues],
                  SanitizedHeaderValues = lists:map(fun sanitize_header_value/1, EncodedHeaderValues),
                  ConcatHeaderValues = string:join(SanitizedHeaderValues, ", "),
                  HeaderName ++  ": " ++ ConcatHeaderValues
          end,
          UniqueHeaderNames),
    {string:join(Lines, "\n"), UniqueHeaderNames, WithBodyDigest}.


reconstruct_request_signature_string(RequestMethod, RequestURI, SignedHeaders) ->
    SignedPseudoHeaders = request_target_pseudo_headers(RequestMethod, RequestURI),
    reconstruct_signature_string(SignedPseudoHeaders, SignedHeaders).

reconstruct_response_signature_string(SignedHeaders) ->
    reconstruct_signature_string([], SignedHeaders).

reconstruct_signature_string(SignedPseudoHeaders, SignedHeaders) ->
    WithPseudo = SignedPseudoHeaders ++ SignedHeaders,
    WithLowercasedNames = lists:keymap(fun string:to_lower/1, 1, WithPseudo),
    UniqueHeaderNames =
        map_unique(fun ({Name, _Value}) -> Name end, WithLowercasedNames),
    Lines =
        lists:map(
          fun (HeaderName) ->
                  HeaderValues = proplists:get_all_values(HeaderName, WithLowercasedNames),
                  EncodedHeaderValues =
                    [encode_header(HeaderName, HeaderValue)
                     || HeaderValue <- HeaderValues],
                  SanitizedHeaderValues = lists:map(fun sanitize_header_value/1, EncodedHeaderValues),
                  ConcatHeaderValues = string:join(SanitizedHeaderValues, ", "),
                  HeaderName ++  ": " ++ ConcatHeaderValues
          end,
          UniqueHeaderNames),
    string:join(Lines, "\n").


is_mandatorily_signed_header({HeaderName, _HeaderValue}) ->
    lists:member(HeaderName, ?MANDATORILY_SIGNED_HEADER_NAMES).

request_target_pseudo_headers(RequestMethod, RequestURI) ->
    [{"(request-target)", string:to_lower(RequestMethod) ++ " " ++ RequestURI}].

sanitize_header_value(Value) ->
    compress_latin1_whitespaces( trim_latin1_whitespaces(Value) ).

trim_latin1_whitespaces(Value) ->
    re:replace(Value, "(^\\s+)|(\\s+$)", "", [global, {return, list}]).

compress_latin1_whitespaces(Value) ->
    re:replace(Value, "\\s+", " ", [global, {return, list}]).

map_unique(Fun, List) ->
    map_unique_recur(Fun, List, []).

map_unique_recur(Fun, [H|T], Acc) ->
    V = Fun(H),
    case lists:member(V, Acc) of
        true -> map_unique_recur(Fun, T, Acc);
        false -> map_unique_recur(Fun, T, [V|Acc])
    end;
map_unique_recur(_Fun, [], Acc) ->
    lists:reverse(Acc).

encode_authorization_signature_params(Params) ->
    string:join(
      lists:map(
        fun ({K, V}) ->
                K ++ "=\"" ++ V ++ "\"" % TODO escape V (and K?)
        end,
        Params),
      ",").

decode_authorization_signature_params(EncodedParams) ->
    MatchResult =
        re:run(
          EncodedParams,
          "(?<name>keyId|algorithm|headers|signature)=\"(?<value>[^\"]+)\"",
          [global, {capture,all_names,list}]),

    case MatchResult of
        {match, Pairs} ->
            lists:map(fun list_to_tuple/1, Pairs);
        nomatch ->
            []
    end.

encode_signed_header_names(SignedHeaderNames) ->
    string:join(SignedHeaderNames, " ").

decode_signed_header_names(EncodedSignedHeaderNames) ->
    re:split(EncodedSignedHeaderNames, " ", [trim, {return, list}]).

kvlists_fetch(Key, List) ->
    {Key, Value} = lists:keyfind(Key, 1, List),
    Value.

kvlists_find(Key, List) ->
    case lists:keyfind(Key, 1, List) of
        {Key, Value} -> {ok, Value};
        false -> error
    end.

%kvlists_take_all(Key, List) ->
%    kvlists_take_all_recur(Key, List, [], []).
%
%kvlists_take_all_recur(Key, [{Key, Value} | T], TakenAcc, Acc) ->
%    kvlists_take_all_recur(Key, T, [Value | TakenAcc], Acc);
%kvlists_take_all_recur(Key, [KV | T], TakenAcc, Acc) ->
%    kvlists_take_all_recur(Key, T, TakenAcc, [KV | Acc]);
%kvlists_take_all_recur(_Key, [], TakenAcc, Acc) ->
%    {lists:reverse(TakenAcc), lists:reverse(Acc)}.

kvlists_take_all_with(Predicate, List) ->
    kvlists_take_all_with_recur(Predicate, List, [], []).

kvlists_take_all_with_recur(Predicate, [{Key, Value} | T], TakenAcc, Acc) ->
    case Predicate(Key) of
        true ->  kvlists_take_all_with_recur(Predicate, T, [{Key, Value} | TakenAcc], Acc);
        false -> kvlists_take_all_with_recur(Predicate, T, TakenAcc, [{Key, Value} | Acc])
    end;
kvlists_take_all_with_recur(_Key, [], TakenAcc, Acc) ->
    {lists:reverse(TakenAcc), lists:reverse(Acc)}.

sign({"hmac-sha256", Key}, Data) ->
    {"hmac-sha256", base64:encode_to_string(crypto:hmac(sha256, Key, Data))}.

-ifdef(TEST).

rfc_draft_example1_similar_signing_test() ->
    ExpectedSignatureString =
        "(request-target): get /foo\n"
        "host: example.org\n"
        "date: Tue, 07 Jun 2014 20:51:35 GMT\n"
        "x-example: Example header with some whitespace.\n"
        "cache-control: max-age=60, must-revalidate",

    {SignatureString, _SignedHeaderNames} =
        request_signature_string(
          "GET", "/foo",
          [{"Host", "example.org"},
           {"Date", "Tue, 07 Jun 2014 20:51:35 GMT"},
           {"X-Example", "Example header\n  with some whitespace."},
           {"Cache-Control", "max-age=60"},
           {"Cache-Control", "must-revalidate"}]),

    ?assertEqual(ExpectedSignatureString, SignatureString).

-endif.
