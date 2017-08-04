-module(backwater_http_signatures).

-include_lib("backwater_common.hrl").

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

-define(KEY_ID, <<"default">>).
-define(ALGORITHM, <<"hmac-sha256">>).

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

-type config() :: #{ key := binary() }.
-export_type([config/0]).

-type message() :: #{ fake_headers := #{ binary() => binary() },
                      real_headers := #{ binary() => binary() }  }.
-export_type([message/0]).

-type header_list() :: [{binary(), binary()}].
-export_type([header_list/0]).

-type header_map() :: #{ binary() => binary() }.
-export_type([header_map/0]).

-type maybe_uncanonical_headers() ::
        header_list() | header_map() | {headers | ci_headers, header_list() | header_map()}.
-export_type([maybe_uncanonical_headers/0]).

-type message_validation_success() :: {ok, SignedHeaderNames :: [binary()]}.
-export_type([message_validation_success/0]).

-type request_validation_failure() :: auth_parse_failure() | validation_failure().
-export_type([request_validation_failure/0]).

-type response_validation_failure() :: sig_parse_failure() | validation_failure().
-export_type([response_validation_failure/0]).

-type body_validation_failure() :: wrong_body_digest | invalid_body_digest.
-export_type([body_validation_failure/0]).

-type auth_parse_failure() :: invalid_auth_type | missing_authorization_header | header_params_failure().
-export_type([auth_parse_failure/0]).

-type sig_parse_failure() :: missing_signature_header | header_params_failure().
-export_type([sig_parse_failure/0]).

-type header_params_failure() :: invalid_header_params.
-export_type([header_params_failure/0]).

-type validation_failure() :: key_id_failure().
-export_type([validation_failure/0]).

-type key_id_failure() :: unknown_key | algorithm_failure().
-export_type([key_id_failure/0]).

-type algorithm_failure() :: unknown_algorithm | headers_failure().
-export_type([algorithm_failure/0]).

-type headers_failure() :: missing_signed_header_list | mandatory_headers_failure().
-export_type([headers_failure/0]).

-type mandatory_headers_failure() :: ({missing_mandatory_header, binary()} |
                                      mandatorily_signed_headers_failure()).
-export_type([mandatory_headers_failure/0]).

-type mandatorily_signed_headers_failure() :: ({missing_mandatorily_signed_header, binary()} |
                                               signature_failure()).
-export_type([mandatorily_signed_headers_failure/0]).

-type signature_failure() :: invalid_signature | signature_string_failure().
-export_type([signature_failure/0]).

-type signature_string_failure() :: {missing_header, binary()}.
-export_type([signature_string_failure/0]).

-type params() :: #{ binary() => binary() | [binary()] }.
-export_type([params/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec config(binary()) -> config().
config(Key) ->
    #{ key => Key }.

-spec new_request_msg(binary(), binary(), maybe_uncanonical_headers()) -> message().
new_request_msg(Method, PathWithQs, Headers) ->
    FakeHeaders = #{ ?OPAQUE_BINARY(<<"(request-target)">>) => request_target(Method, PathWithQs) },
    RealHeaders = canonical_headers(Headers),
    new_msg(FakeHeaders, RealHeaders).

-spec new_response_msg(non_neg_integer(), maybe_uncanonical_headers()) -> message().
new_response_msg(StatusCode, Headers) ->
    FakeHeaders = #{ ?OPAQUE_BINARY(<<"(response-status)">>) => response_status(StatusCode) },
    RealHeaders = canonical_headers(Headers),
    new_msg(FakeHeaders, RealHeaders).

-spec validate_request_signature(config(), message())
        -> {ok, SignedHeaderNames :: [binary()]} |
           {error, {Reason :: request_validation_failure(),
                    ChallengeHeaders :: #{ binary() := binary() }}}.
validate_request_signature(Config, Msg) ->
    AuthorizationHeaderLookup = find_real_msg_header(<<"authorization">>, Msg),
    Result =
        case parse_authorization_header(AuthorizationHeaderLookup) of
            {ok, Params} ->
                validate_params(Config, Params, Msg);
            {error, Reason} ->
                {error, Reason}
        end,
    request_validation_result(Result, Msg).

-spec validate_response_signature(config(), message())
        -> {ok, SignedHeaderNames :: [binary()]} |
           {error, Reason :: response_validation_failure()}.
validate_response_signature(Config, Msg) ->
    SignatureHeaderLookup = find_real_msg_header(<<"signature">>, Msg),
    case parse_signature_header(SignatureHeaderLookup) of
        {ok, Params} ->
            validate_params(Config, Params, Msg);
        {error, Reason} ->
            {error, Reason}
    end.

-spec validate_msg_body(message(), binary()) -> ok | {error, body_validation_failure()}.
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

-spec sign_request(config(), message(), binary()) -> message().
sign_request(Config, Msg1, Body) ->
    BodyDigest = body_digest(Body),
    Msg2 = remove_real_msg_headers([<<"authorization">>, <<"date">>], Msg1),
    Msg3 = add_real_msg_headers(#{ <<"digest">> => BodyDigest, <<"date">> => rfc1123() }, Msg2),
    AuthorizationHeaderValue = generate_authorization_header_value(Config, Msg3),
    add_real_msg_headers(#{ ?OPAQUE_BINARY(<<"authorization">>) => AuthorizationHeaderValue }, Msg3).

-spec sign_response(config(), message(), binary()) -> message().
sign_response(Config, Msg1, Body) ->
    BodyDigest = body_digest(Body),
    Msg2 = remove_real_msg_headers([<<"date">>, <<"signature">>], Msg1),
    Msg3 = add_real_msg_headers(#{ <<"digest">> => BodyDigest, <<"date">> => rfc1123() }, Msg2),
    SignatureHeaderValue = generate_signature_header_value(Config, Msg3),
    add_real_msg_headers(#{ ?OPAQUE_BINARY(<<"signature">>) => SignatureHeaderValue}, Msg3).

-spec get_real_msg_headers(message()) -> header_map().
get_real_msg_headers(Msg) ->
    #{ real_headers := Map } = Msg,
    Map.

-spec list_real_msg_headers(message()) -> header_list().
list_real_msg_headers(Msg) ->
    maps:to_list( get_real_msg_headers(Msg) ).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Messages
%% ------------------------------------------------------------------

-spec request_target(binary(), binary()) -> binary().
request_target(Method, PathWithQs) ->
    CiMethod = backwater_util:latin1_binary_to_lower(Method),
    ?OPAQUE_BINARY(<<CiMethod/binary, " ", PathWithQs/binary>>).

-spec response_status(non_neg_integer()) -> binary().
response_status(StatusCode) ->
    integer_to_binary(StatusCode).

-spec new_msg(header_map(), header_map()) -> message().
new_msg(FakeHeaders, RealHeaders) ->
    #{ fake_headers => FakeHeaders,
       real_headers => RealHeaders }.

-spec find_msg_header(binary(), message()) -> {ok, binary()} | error.
find_msg_header(CiName, Msg) ->
    #{ fake_headers := Map } = Msg,
    case maps:find(CiName, Map) of
        {ok, Value} -> {ok, Value};
        error -> find_real_msg_header(CiName, Msg)
    end.

-spec find_real_msg_header(binary(), message()) -> {ok, binary()} | error.
find_real_msg_header(CiName, Msg) ->
    #{ real_headers := Map } = Msg,
    maps:find(CiName, Map).

-spec remove_real_msg_headers([binary()], message()) -> message().
remove_real_msg_headers(CiNames, Msg) ->
    #{ real_headers := Map1 } = Msg,
    Map2 = maps:without(CiNames, Map1),
    Msg#{ real_headers := Map2 }.

-spec add_real_msg_headers(header_map(), message()) -> message().
add_real_msg_headers(ExtraMap, Msg) ->
    #{ real_headers := Map1 } = Msg,
    Map2 = maps:merge(Map1, ExtraMap),
    Msg#{ real_headers := Map2 }.

-spec list_fake_msg_header_names(message()) -> [binary()].
list_fake_msg_header_names(Msg) ->
    #{ fake_headers := Map } = Msg,
    maps:keys(Map).

-spec list_real_msg_header_names(message()) -> [binary()].
list_real_msg_header_names(Msg) ->
    #{ real_headers := Map } = Msg,
    maps:keys(Map).

-spec list_msg_headers(message()) -> header_list().
list_msg_headers(Msg) ->
    #{ fake_headers := MapA,
       real_headers := MapB } = Msg,
    Merged = maps:merge(MapB, MapA),
    maps:to_list(Merged).

-spec list_msg_header_names(message()) -> [binary()].
list_msg_header_names(Msg) ->
    #{ fake_headers := MapA,
       real_headers := MapB } = Msg,
    lists:usort(maps:keys(MapA) ++ maps:keys(MapB)).

-spec canonical_headers(maybe_uncanonical_headers()) -> header_map().
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

-spec ci_headers_list(header_list()) -> header_list().
ci_headers_list(List) ->
    lists:keymap(fun backwater_util:latin1_binary_to_lower/1, 1, List).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validation
%% ------------------------------------------------------------------

-spec decode_signature_auth_params(binary()) -> {ok, params()} | {error, header_params_failure()}.
decode_signature_auth_params(Encoded) ->
    case backwater_http_header_params:decode(Encoded) of
        {ok, BinParams} ->
            Params = maps:map(fun decode_signature_param_value/2, BinParams),
            {ok, Params};
        error ->
            {error, invalid_header_params}
    end.

-spec parse_authorization_header({ok, binary()} | error)
        -> {ok, params()} | {error, auth_parse_failure()}.
parse_authorization_header({ok, <<"Signature ", EncodedParams/binary>>}) ->
    decode_signature_auth_params(EncodedParams);
parse_authorization_header({ok, _OtherAuth}) ->
    {error, invalid_auth_type};
parse_authorization_header(error) ->
    {error, missing_authorization_header}.

-spec parse_digest({ok, binary()} | error) -> {sha256, binary()} | invalid.
parse_digest({ok, <<"SHA-256=", EncodedDigest/binary>>}) ->
    % TODO error?
    Digest = base64:decode(EncodedDigest),
    {sha256, Digest};
parse_digest(_) ->
    invalid.

-spec parse_signature_header({ok, binary()} | error)
        -> {ok, params()} | {error, sig_parse_failure()}.
parse_signature_header({ok, EncodedParams}) ->
    decode_signature_auth_params(EncodedParams);
parse_signature_header(error) ->
    {error, missing_signature_header}.

-spec decode_signature_param_value(binary(), binary()) -> [binary()] | binary().
decode_signature_param_value(<<"headers">>, EncodedList) ->
    binary:split(EncodedList, <<" ">>, [global, trim_all]);
decode_signature_param_value(<<"signature">>, EncodedSignature) ->
    % TODO error?
    base64:decode(EncodedSignature);
decode_signature_param_value(_Key, Value) ->
    Value.

-spec validate_params(config(), params(), message())
        -> message_validation_success() | {error, key_id_failure()}.
validate_params(Config, Params, Msg) ->
    validate_key_id(Config, Params, Msg).

-spec validate_key_id(config(), params(), message())
        -> message_validation_success() | {error, key_id_failure()}.
validate_key_id(Config, #{ <<"keyId">> := ?KEY_ID } = Params, Msg) ->
    validate_algorithm(Config, Params, Msg);
validate_key_id(_Config, _Params, _Msg) ->
    {error, unknown_key}.

-spec validate_algorithm(config(), params(), message())
        -> message_validation_success() | {error, algorithm_failure()}.
validate_algorithm(Config, #{ <<"algorithm">> := ?ALGORITHM } = Params, Msg) ->
    validate_signed_headers(Config, Params, Msg);
validate_algorithm(_Config, _Params, _Msg) ->
    {error, unknown_algorithm}.

-spec validate_signed_headers(config(), params(), message())
        -> message_validation_success() | {error, headers_failure()}.
validate_signed_headers(Config, #{ <<"headers">> := _ } = Params, Msg) ->
    validate_mandatory_headers(Config, Params, Msg);
validate_signed_headers(_Config, _Params, _Msg) ->
    {error, missing_signed_header_list}.

-spec validate_mandatory_headers(config(), params(), message())
        -> message_validation_success() | {error, mandatory_headers_failure()}.
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

-spec validate_mandatorily_signed_headers(config(), params(), message())
        -> message_validation_success() | {error, mandatorily_signed_headers_failure()}.
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

-spec validate_signature(config(), params(), message())
        -> message_validation_success() | {error, signature_failure()}.
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

-spec signed_header_names(params(), message()) -> [binary()].
signed_header_names(Params, Msg) ->
    RealHeaderNames = list_real_msg_header_names(Msg),
    #{ <<"headers">> := SignedHeaderNames } = Params,
    [Name || Name <- RealHeaderNames, lists:member(Name, SignedHeaderNames)].

-spec request_validation_result(message_validation_success() | {error, request_validation_failure()},
                                message())
        -> message_validation_success() | {error, {request_validation_failure(), header_map()}}.
request_validation_result({ok, SignedHeaderNames}, _RequestMsg) ->
    {ok, SignedHeaderNames};
request_validation_result({error, Reason}, RequestMsg) ->
    AuthChallengeHeaders = auth_challenge_headers(RequestMsg),
    {error, {Reason, AuthChallengeHeaders}}.

-spec auth_challenge_headers(message()) -> header_map().
auth_challenge_headers(RequestMsg) ->
    FakeHeaderNamesToSign = list_fake_msg_header_names(RequestMsg),
    RealHeaderNames = list_real_msg_header_names(RequestMsg),
    RealHeaderNamesToSign =
            [Name || Name <- RealHeaderNames,
                     lists:member(Name, ?VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES) orelse
                     lists:member(Name, ?VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES_IF_PRESENT)],

    HeaderNamesToSign = lists:usort(FakeHeaderNamesToSign ++ RealHeaderNamesToSign),
    EncodedHeaderNamesToSign = iolist_to_binary(lists:join(" ", HeaderNamesToSign)),
    Params = #{ <<"realm">> => <<"backwater">>,
                <<"headers">> => EncodedHeaderNamesToSign },
    BinParams = backwater_http_header_params:encode(Params),
    #{ ?OPAQUE_BINARY(<<"www-authenticate">>) => ?OPAQUE_BINARY(<<"Signature ", BinParams/binary>>) }.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Signing
%% ------------------------------------------------------------------

-spec rfc1123() -> binary().
rfc1123() ->
    CurrTime = erlang:universaltime(),
    String = httpd_util:rfc1123_date(CurrTime),
    list_to_binary(String).

-spec generate_authorization_header_value(config(), message()) -> nonempty_binary().
generate_authorization_header_value(Config, Msg) ->
    EncodedParams = generate_signature_header_value(Config, Msg),
    ?OPAQUE_BINARY(<<"Signature ", EncodedParams/binary>>).

-spec generate_signature_header_value(config(), message()) -> binary().
generate_signature_header_value(Config, Msg) ->
    #{ key := Key } = Config,
    SignedHeaderNames = list_msg_header_names(Msg),
    {ok, SignatureIoData} = build_signature_iodata(SignedHeaderNames, Msg),
    Signature = crypto:hmac(sha256, Key, SignatureIoData),
    SignatureParams =
        #{ ?OPAQUE_BINARY(<<"keyId">>) => ?KEY_ID,
           ?OPAQUE_BINARY(<<"algorithm">>) => ?ALGORITHM,
           ?OPAQUE_BINARY(<<"headers">>) => SignedHeaderNames,
           ?OPAQUE_BINARY(<<"signature">>) => Signature },
    encode_signature_auth_params(SignatureParams).

-spec encode_signature_auth_params(params()) -> binary().
encode_signature_auth_params(Params) ->
    BinParams = maps:map(fun encode_signature_param_value/2, Params),
    backwater_http_header_params:encode(BinParams).

-spec encode_signature_param_value(binary(), term()) -> binary().
encode_signature_param_value(<<"headers">>, List) ->
    lists:join(" ", List);
encode_signature_param_value(<<"signature">>, Signature) ->
    base64:encode(Signature);
encode_signature_param_value(_Key, Value) ->
    Value.

-spec body_digest(binary()) -> nonempty_binary().
body_digest(Body) ->
    Digest = crypto:hash(sha256, Body),
    EncodedDigest = base64:encode(Digest),
    <<"SHA-256=", EncodedDigest/binary>>.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Signature String
%% ------------------------------------------------------------------

-spec build_signature_iodata([binary()], message())
        -> {ok, iodata()} | {error, signature_string_failure()}.
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
