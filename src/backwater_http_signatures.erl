-module(backwater_http_signatures).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([config/1]).
-export([new_request_msg/3]).
-export([new_response_msg/2]).
-export([validate_request_signature/2]).
-export([validate_response_signature/2]).
-export([validate_msg_body/2]).
-export([sign_request/3]).
-export([sign_response/3]).
-export([get_real_msg_headers/1]).
-export([list_real_msg_headers/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES,
        [<<"date">>,
         <<"digest">>]).

-define(VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES_IF_PRESENT,
        [<<"accept">>,
         <<"content-type">>,
         <<"content-encoding">>]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

%-type config() ::
%        #{ key := binary() }.
%
%-type message() :: #{ fake_headers := #{ binary() => iodata() },
%                      real_headers := #{ binary() => binary() }  }.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

config(Key) ->
    #{ key => Key }.

new_request_msg(Method, PathWithQs, Headers) ->
    FakeHeaders = #{ <<"(request-target)">> => request_target(Method, PathWithQs) },
    RealHeaders = canonical_headers(Headers),
    new_msg(FakeHeaders, RealHeaders).

new_response_msg(StatusCode, Headers) ->
    FakeHeaders = #{ <<"(response-status)">> => response_status(StatusCode) },
    RealHeaders = canonical_headers(Headers),
    new_msg(FakeHeaders, RealHeaders).

validate_request_signature(Config, Msg) ->
    AuthorizationHeaderLookup = find_real_msg_header(<<"authorization">>, Msg),
    case parse_authorization_header(AuthorizationHeaderLookup) of
        {ok, Params} ->
            validate_params(Config, Params, Msg);
        {error, Reason} ->
            {error, Reason}
    end.

validate_response_signature(Config, Msg) ->
    SignatureHeaderLookup = find_real_msg_header(<<"signature">>, Msg),
    case parse_signature_header(SignatureHeaderLookup) of
        {ok, Params} ->
            validate_params(Config, Params, Msg);
        {error, Reason} ->
            {error, Reason}
    end.


validate_msg_body(Msg, Body) ->
    DigestLookup = find_real_msg_header(<<"digest">>, Msg),
    case parse_digest(DigestLookup) of
        {sha256, Digest} ->
            ExpectedDigest = crypto:hash(sha256, Body),
            case Digest =:= ExpectedDigest of
                true -> ok;
                false -> {error, wrong_body_digest}
            end;
        invalid ->
            {error, invalid_body_digest}
    end.

sign_request(Config, Msg1, Body) ->
    BodyDigest = body_digest(Body),
    Msg2 = remove_real_msg_headers([<<"authorization">>, <<"date">>], Msg1),
    Msg3 = add_real_msg_headers(#{ <<"digest">> => BodyDigest, <<"date">> => rfc1123() }, Msg2),
    AuthorizationHeaderValue = generate_authorization_header_value(Config, Msg3),
    add_real_msg_headers(#{ <<"authorization">> => AuthorizationHeaderValue }, Msg3).

sign_response(Config, Msg1, Body) ->
    BodyDigest = body_digest(Body),
    Msg2 = remove_real_msg_headers([<<"date">>, <<"signature">>], Msg1),
    Msg3 = add_real_msg_headers(#{ <<"digest">> => BodyDigest, <<"date">> => rfc1123() }, Msg2),
    SignatureHeaderValue = generate_signature_header_value(Config, Msg3),
    add_real_msg_headers(#{ <<"signature">> => SignatureHeaderValue}, Msg3).

get_real_msg_headers(Msg) ->
    #{ real_headers := Map } = Msg,
    Map.

list_real_msg_headers(Msg) ->
    maps:to_list( get_real_msg_headers(Msg) ).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Messages
%% ------------------------------------------------------------------

request_target(Method, PathWithQs) ->
    CiMethod = backwater_util:latin1_binary_to_lower(Method),
    [CiMethod, " ", PathWithQs].

response_status(StatusCode) ->
    integer_to_binary(StatusCode).

new_msg(FakeHeaders, RealHeaders) ->
    #{ fake_headers => FakeHeaders,
       real_headers => RealHeaders }.

find_msg_header(CiName, Msg) ->
    #{ fake_headers := Map } = Msg,
    case maps:find(CiName, Map) of
        {ok, Value} -> {ok, Value};
        error -> find_real_msg_header(CiName, Msg)
    end.

find_real_msg_header(CiName, Msg) ->
    #{ real_headers := Map } = Msg,
    maps:find(CiName, Map).

remove_real_msg_headers(CiNames, Msg) ->
    #{ real_headers := Map1 } = Msg,
    Map2 = maps:without(CiNames, Map1),
    Msg#{ real_headers := Map2 }.

add_real_msg_headers(ExtraMap, Msg) ->
    #{ real_headers := Map1 } = Msg,
    Map2 = maps:merge(Map1, ExtraMap),
    Msg#{ real_headers := Map2 }.

list_real_msg_header_names(Msg) ->
    #{ real_headers := Map } = Msg,
    maps:keys(Map).

list_msg_headers(Msg) ->
    #{ fake_headers := MapA,
       real_headers := MapB } = Msg,
    Merged = maps:merge(MapB, MapA),
    maps:to_list(Merged).

list_msg_header_names(Msg) ->
    #{ fake_headers := MapA,
       real_headers := MapB } = Msg,
    lists:usort(maps:keys(MapA) ++ maps:keys(MapB)).

canonical_headers(List1) when is_list(List1) ->
    canonical_headers({headers, List1});
canonical_headers(Map) when is_map(Map) ->
    canonical_headers({headers, Map});
canonical_headers({headers, List1}) when is_list(List1) ->
    List2 = ci_headers_list(List1),
    canonical_headers({ci_headers, List2});
canonical_headers({headers, Map}) when is_map(Map) ->
    List = maps:to_list(Map),
    canonical_headers({headers, List});
canonical_headers({ci_headers, List}) when is_list(List) ->
    maps:from_list(List);
canonical_headers({ci_headers, Map}) when is_map(Map) ->
    Map.

ci_headers_list(List) ->
    lists:keymap(fun backwater_util:latin1_binary_to_lower/1, 1, List).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validation
%% ------------------------------------------------------------------

decode_signature_auth_params(Encoded) ->
    case backwater_http_header_params:decode(Encoded) of
        {ok, BinParams} ->
            Params = maps:map(fun decode_signature_param_value/2, BinParams),
            {ok, Params};
        error ->
            error
    end.

parse_authorization_header({ok, <<"Signature ", EncodedParams/binary>>}) ->
    decode_signature_auth_params(EncodedParams);
parse_authorization_header({ok, _OtherAuth}) ->
    {error, invalid_auth_type};
parse_authorization_header(error) ->
    {error, missing_authorization_header}.

parse_digest({ok, <<"SHA-256=", EncodedDigest/binary>>}) ->
    % TODO error?
    Digest = base64:decode(EncodedDigest),
    {sha256, Digest};
parse_digest(_) ->
    invalid.

parse_signature_header({ok, EncodedParams}) ->
    decode_signature_auth_params(EncodedParams);
parse_signature_header(error) ->
    {error, missing_signature_header}.

decode_signature_param_value(<<"headers">>, EncodedList) ->
    binary:split(EncodedList, <<" ">>, [global, trim_all]);
decode_signature_param_value(<<"signature">>, EncodedSignature) ->
    % TODO error?
    base64:decode(EncodedSignature);
decode_signature_param_value(_Key, Value) ->
    Value.

validate_params(Config, Params, Msg) ->
    validate_key_id(Config, Params, Msg).

validate_key_id(Config, #{ <<"keyId">> := <<"key">> } = Params, Msg) ->
    validate_algorithm(Config, Params, Msg);
validate_key_id(_Config, _Params, _Msg) ->
    {error, unknown_key}.

validate_algorithm(Config, #{ <<"algorithm">> := <<"hmac-sha256">> } = Params, Msg) ->
    validate_signed_headers(Config, Params, Msg);
validate_algorithm(_Config, _Params, _Msg) ->
    {error, unknown_algorithm}.

validate_signed_headers(Config, #{ <<"headers">> := _ } = Params, Msg) ->
    validate_mandatory_headers(Config, Params, Msg);
validate_signed_headers(_Config, _Params, _Msg) ->
    {error, missing_signed_header_list}.

validate_mandatory_headers(Config, #{ <<"headers">> := SignedHeaderNames } = Params, Msg) ->
    MissingMandatory =
        backwater_util:lists_anymap(
          fun (Name) ->
                  (not lists:member(Name, SignedHeaderNames))
                  andalso {true, Name}
          end,
          ?VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES),

    case MissingMandatory of
        {true, Name} ->
            {error, {missing_mandatory_header, Name}};
        false ->
            validate_mandatorily_signed_headers(Config, Params, Msg)
    end.

validate_mandatorily_signed_headers(Config, #{ <<"headers">> := SignedHeaderNames } = Params, Msg) ->
    AllHeaders = list_msg_headers(Msg),
    MissingMandatory =
        backwater_util:lists_anymap(
          fun ({Name, _Value}) ->
                  lists:member(Name, ?VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES_IF_PRESENT)
                  andalso not lists:member(Name, SignedHeaderNames)
                  andalso {true, Name}
          end,
          AllHeaders),

    case MissingMandatory of
        {true, Name} ->
            {error, {missing_mandatorily_signed_header, Name}};
        false ->
            validate_signature(Config, Params, Msg)
    end.

validate_signature(Config, #{ <<"headers">> := SignedHeaderNames, <<"signature">> := Signature } = Params,
                   Msg) ->
    case build_signature_iodata(SignedHeaderNames, Msg) of
        {error, Reason} ->
            {error, Reason};
        {ok, IoData} ->
            #{ key := Key } = Config,
            ExpectedSignature = crypto:hmac(sha256, Key, IoData),
            case ExpectedSignature =:= Signature of
                true -> {ok, signed_header_names(Params, Msg)};
                false -> {error, invalid_signature}
            end
    end.

signed_header_names(Params, Msg) ->
    RealHeaderNames = list_real_msg_header_names(Msg),
    #{ <<"headers">> := SignedHeaderNames } = Params,
    [Name || Name <- RealHeaderNames, lists:member(Name, SignedHeaderNames)].

%% ------------------------------------------------------------------
%% Internal Function Definitions - Signing
%% ------------------------------------------------------------------

rfc1123() ->
    CurrTime = erlang:universaltime(),
    httpd_util:rfc1123_date(CurrTime).

generate_authorization_header_value(Config, Msg) ->
    EncodedParams = generate_signature_header_value(Config, Msg),
    <<"Signature ", EncodedParams/binary>>.

generate_signature_header_value(Config, Msg) ->
    #{ key := Key } = Config,
    SignedHeaderNames = list_msg_header_names(Msg),
    {ok, SignatureIoData} = build_signature_iodata(SignedHeaderNames, Msg),
    Signature = crypto:hmac(sha256, Key, SignatureIoData),
    SignatureParams =
        #{ <<"keyId">> => <<"key">>,
           <<"algorithm">> => <<"hmac-sha256">>,
           <<"headers">> => SignedHeaderNames,
           <<"signature">> => Signature },
    encode_signature_auth_params(SignatureParams).

encode_signature_auth_params(Params) ->
    BinParams = maps:map(fun encode_signature_param_value/2, Params),
    backwater_http_header_params:encode(BinParams).

encode_signature_param_value(<<"headers">>, List) ->
    lists:join(" ", List);
encode_signature_param_value(<<"signature">>, Signature) ->
    base64:encode(Signature);
encode_signature_param_value(_Key, Value) ->
    Value.

body_digest(Body) ->
    Digest = crypto:hash(sha256, Body),
    EncodedDigest = base64:encode(Digest),
    <<"SHA-256=", EncodedDigest/binary>>.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Signature String
%% ------------------------------------------------------------------

build_signature_iodata(SignedHeaderNames, Msg) ->
    BuildPartsResult =
        backwater_util:lists_allmap(
          fun (Name) ->
                  CiName = backwater_util:latin1_binary_to_lower(Name),
                  case find_msg_header(CiName, Msg) of
                      {ok, Value} ->
                          TrimmedValue = backwater_util:latin1_binary_trim_whitespaces(Value),
                          {true, [CiName, ": ", TrimmedValue]};
                      error ->
                          % missing header
                          {false, Name}
                  end
          end,
          SignedHeaderNames),

    case BuildPartsResult of
        {false, Name} ->
            {error, {missing_header, Name}};
        {true, Parts} ->
            OnePerLine = lists:join("\n", Parts),
            {ok, OnePerLine}
    end.
