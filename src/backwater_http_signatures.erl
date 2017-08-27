%% Copyright (c) 2017 Guilherme Andrade <backwater@gandrade.net>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy  of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

-module(backwater_http_signatures).

-include_lib("backwater_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% @doc The code in this module is based on the "http signatures"[1]
%% IETF draft, version nr. 7, by M. Cavage, published on July 17, 2017.
%%
%% A few things to point out:
%% - The only algorithm supported as of now is "hmac-sha256".
%% - There's a single key identifier: "default".
%% - SHA-256 body digests are mandatory and only this kind of checksum
%%   is yet supported.
%% - HTTP response status code is a mandatory part of response signatures,
%%   through use of a "(response-status)" pseudo-header.
%% - Custom header "x-request-id" is a mandatory part of the signature of
%%   both request and response signatures, and it is intended to be filled
%%   with an unique non-empty string per request; validation of response
%%   signature is also dependent upon its "x-request-id" being an exact
%%   match to the request's.
%% - Dates are not (yet?) used.
%% - Multiple header pairs under the same name, with names being case
%%   insensitive, are not supported.
%%
%% Under its current configuration, replay attacks are plentifully possible
%% under HTTP but, bugs aside and presuming a good quality well-kept secret,
%% the following kinds of mischief are to be detectable:
%% - forged requests
%% - forged responses
%% - in-flight request modification
%% - in-flight response modification (save for the status line reason phrase)
%%
%% Which is pretty good but rather incomplete. Best to use HTTPS to start with.
%%
%% [1]: https://tools.ietf.org/html/draft-cavage-http-signatures-07

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([config/1]).
-export([new_request_msg/3]).
-export([new_response_msg/2]).
-export([validate_request_signature/2]).
-export([validate_response_signature/2]).
-export([validate_signed_msg_body/2]).
-export([sign_request/4]).
-export([sign_response/4]).
-export([get_real_msg_headers/1]).
-export([list_real_msg_headers/1]).
-export([is_header_signed_in_signed_msg/2]).
-export([get_request_auth_challenge_headers/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(KEY_ID, <<"default">>).
-define(ALGORITHM, <<"hmac-sha256">>).

-define(VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES,
        [<<"digest">>,
         <<"x-request-id">>]).

-define(VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES_IF_PRESENT,
        [<<"accept">>,
         <<"content-type">>,
         <<"content-encoding">>,
         <<"content-length">>]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type algorithm_failure() :: unknown_algorithm | headers_failure().
-export_type([algorithm_failure/0]).

-type auth_parse_failure() ::
        invalid_auth_type | missing_authorization_header | header_params_failure().
-export_type([auth_parse_failure/0]).

-opaque config() :: #{ key := binary() }.
-export_type([config/0]).

-type header_list() :: [{binary(), binary()}].
-export_type([header_list/0]).

-type header_map() :: #{ binary() => binary() }.
-export_type([header_map/0]).

-type header_params_failure() :: invalid_header_params.
-export_type([header_params_failure/0]).

-type headers_failure() :: missing_signed_header_list | mandatory_headers_failure().
-export_type([headers_failure/0]).

-type key_id_failure() :: unknown_key | algorithm_failure().
-export_type([key_id_failure/0]).

-type mandatorily_signed_headers_failure() :: ({missing_mandatorily_signed_header, binary()} |
                                               signature_failure()).
-export_type([mandatorily_signed_headers_failure/0]).

-type mandatory_headers_failure() :: ({missing_mandatory_header, binary()} |
                                      mandatorily_signed_headers_failure()).
-export_type([mandatory_headers_failure/0]).

-type maybe_uncanonical_headers() ::
        header_list() | header_map() | {headers | ci_headers, header_list() | header_map()}.
-export_type([maybe_uncanonical_headers/0]).

-type message() :: unsigned_message() | signed_message().
-export_type([unsigned_message/0]).

-type message_validation_success() :: {ok, signed_message()}.
-export_type([message_validation_success/0]).

-type response_validation_failure() :: request_id_validation_failure().
-export_type([response_validation_failure/0]).

-type request_id_validation_failure() ::
        mismatched_request_id | missing_request_id | sig_parse_failure() | validation_failure().
-export_type([request_id_validation_failure/0]).

-type request_validation_failure() :: auth_parse_failure() | validation_failure().
-export_type([request_validation_failure/0]).

-type sig_parse_failure() :: missing_signature_header | header_params_failure().
-export_type([sig_parse_failure/0]).

-opaque signed_message() ::
    #{ pseudo_headers := #{ binary() => binary() },
       real_headers := #{ binary() => binary() },
       config := config(),
       request_id := binary(),
       signed_header_names := [binary()],
       body_digest := binary() }.
-export_type([signed_message/0]).

-opaque unsigned_message() ::
    #{ pseudo_headers := #{ binary() => binary() },
       real_headers := #{ binary() => binary() }  }.
-export_type([message/0]).

-type validation_failure() :: key_id_failure().
-export_type([validation_failure/0]).

-type signature_failure() :: invalid_signature | signature_string_failure().
-export_type([signature_failure/0]).

-type signature_string_failure() :: {missing_header, binary()}.
-export_type([signature_string_failure/0]).

-type params() :: #{ binary() => binary() | [binary()] }.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec config(binary()) -> config().
%% @private
config(Secret) ->
    #{ key => Secret }.

-spec new_request_msg(binary(), binary(), maybe_uncanonical_headers()) -> unsigned_message().
%% @private
new_request_msg(Method, EncodedPathWithQs, Headers) ->
    PseudoHeaders = #{ ?OPAQUE_BINARY(<<"(request-target)">>) => request_target(Method, EncodedPathWithQs) },
    RealHeaders = canonical_headers(Headers),
    new_unsigned_msg(PseudoHeaders, RealHeaders).

-spec new_response_msg(non_neg_integer(), maybe_uncanonical_headers()) -> unsigned_message().
%% @private
new_response_msg(StatusCode, Headers) ->
    PseudoHeaders = #{ ?OPAQUE_BINARY(<<"(response-status)">>) => response_status(StatusCode) },
    RealHeaders = canonical_headers(Headers),
    new_unsigned_msg(PseudoHeaders, RealHeaders).

-spec validate_request_signature(config(), message())
        -> message_validation_success() |
           {error, Reason :: request_validation_failure()}.
%% @private
validate_request_signature(Config, RequestMsg) ->
    AuthorizationHeaderLookup = find_real_msg_header(<<"authorization">>, RequestMsg),
    case parse_authorization_header(AuthorizationHeaderLookup) of
        {ok, Params} ->
            validate_params(Config, Params, RequestMsg);
        {error, Reason} ->
            {error, Reason}
    end.

-spec validate_response_signature(signed_message(), message())
        -> message_validation_success() |
           {error, Reason :: response_validation_failure()}.
%% @private
validate_response_signature(SignedRequestMsg, ResponseMsg) ->
    #{ config := Config, request_id := RequestId } = SignedRequestMsg,
    MsgRequestIdLookup = find_real_msg_header(<<"x-request-id">>, ResponseMsg),
    validate_response_request_id(Config, ResponseMsg, RequestId, MsgRequestIdLookup).

-spec validate_signed_msg_body(signed_message(), binary()) -> boolean().
%% @private
validate_signed_msg_body(SignedMsg, Body) ->
    #{ body_digest := BodyDigest } = SignedMsg,
    body_digest(Body) =:= BodyDigest.

-spec sign_request(config(), message(), binary(), binary()) -> signed_message().
%% @private
sign_request(Config, RequestMsg1, Body, RequestId) ->
    BodyDigest = body_digest(Body),
    ExtraSignedHeaders =
        #{ <<"digest">> => BodyDigest,
           <<"x-request-id">> => RequestId },
    RequestMsg2 = remove_real_msg_header(<<"authorization">>, RequestMsg1),
    RequestMsg3 = add_real_msg_headers(ExtraSignedHeaders, RequestMsg2),
    SignedHeaderNames = list_msg_header_names(RequestMsg3),
    AuthorizationHeaderValue = generate_authorization_header_value(Config, RequestMsg3, SignedHeaderNames),
    RequestMsg4 =
        add_real_msg_headers(#{ ?OPAQUE_BINARY(<<"authorization">>) => AuthorizationHeaderValue }, RequestMsg3),
    RequestMsg4#{
      config => Config,
      request_id => RequestId,
      signed_header_names => SignedHeaderNames,
      body_digest => BodyDigest }.

-spec sign_response(config(), message(), binary(), signed_message()) -> signed_message().
%% @private
sign_response(Config, ResponseMsg1, Body, SignedRequestMsg) ->
    #{ request_id := RequestId } = SignedRequestMsg,
    BodyDigest = body_digest(Body),
    ExtraSignedHeaders =
        #{ <<"digest">> => BodyDigest,
           <<"x-request-id">> => RequestId },
    ResponseMsg2 = remove_real_msg_header(<<"signature">>, ResponseMsg1),
    ResponseMsg3 = add_real_msg_headers(ExtraSignedHeaders, ResponseMsg2),
    SignedHeaderNames = list_msg_header_names(ResponseMsg3),
    SignatureHeaderValue = generate_signature_header_value(Config, ResponseMsg3, SignedHeaderNames),
    ResponseMsg4 =
        add_real_msg_headers(#{ ?OPAQUE_BINARY(<<"signature">>) => SignatureHeaderValue}, ResponseMsg3),
    ResponseMsg4#{
      config => Config,
      request_id => RequestId,
      signed_header_names => SignedHeaderNames,
      body_digest => BodyDigest }.

-spec get_real_msg_headers(message()) -> header_map().
%% @private
get_real_msg_headers(Msg) ->
    #{ real_headers := Map } = Msg,
    Map.

-spec list_real_msg_headers(message()) -> header_list().
%% @private
list_real_msg_headers(Msg) ->
    maps:to_list( get_real_msg_headers(Msg) ).

-spec is_header_signed_in_signed_msg(binary(), signed_message()) -> boolean().
%% @private
is_header_signed_in_signed_msg(CiName, SignedMsg) ->
    #{ signed_header_names := SignedHeaderNames } = SignedMsg,
    lists:member(CiName, SignedHeaderNames).

-spec get_request_auth_challenge_headers(message()) -> header_map().
%% @private
get_request_auth_challenge_headers(RequestMsg) ->
    PseudoHeaderNamesToSign = list_pseudo_msg_header_names(RequestMsg),
    RealHeaderNames = list_real_msg_header_names(RequestMsg),
    RealHeaderNamesToSign =
            [Name || Name <- RealHeaderNames,
                     lists:member(Name, ?VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES) orelse
                     lists:member(Name, ?VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES_IF_PRESENT)],

    HeaderNamesToSign = lists:usort(PseudoHeaderNamesToSign ++ RealHeaderNamesToSign),
    EncodedHeaderNamesToSign = iolist_to_binary(lists:join(" ", HeaderNamesToSign)),
    Params = #{ <<"realm">> => <<"backwater">>,
                <<"headers">> => EncodedHeaderNamesToSign },
    BinParams = backwater_http_header_params:encode(Params),
    #{ ?OPAQUE_BINARY(<<"www-authenticate">>) => ?OPAQUE_BINARY(<<"Signature ", BinParams/binary>>) }.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Messages
%% ------------------------------------------------------------------

-spec request_target(binary(), binary()) -> binary().
request_target(Method, EncodedPathWithQs) ->
    CiMethod = backwater_util:latin1_binary_to_lower(Method),
    ?OPAQUE_BINARY(<<CiMethod/binary, " ", EncodedPathWithQs/binary>>).

-spec response_status(non_neg_integer()) -> binary().
response_status(StatusCode) ->
    integer_to_binary(StatusCode).

-spec new_unsigned_msg(header_map(), header_map()) -> unsigned_message().
new_unsigned_msg(PseudoHeaders, RealHeaders) ->
    #{ pseudo_headers => PseudoHeaders,
       real_headers => RealHeaders }.

-spec find_msg_header(binary(), message()) -> {ok, binary()} | error.
find_msg_header(CiName, Msg) ->
    #{ pseudo_headers := Map } = Msg,
    case maps:find(CiName, Map) of
        {ok, Value} -> {ok, Value};
        error -> find_real_msg_header(CiName, Msg)
    end.

-spec find_real_msg_header(binary(), message()) -> {ok, binary()} | error.
find_real_msg_header(CiName, Msg) ->
    #{ real_headers := Map } = Msg,
    maps:find(CiName, Map).

-spec remove_real_msg_header(binary(), message()) -> message().
remove_real_msg_header(CiName, Msg) ->
    #{ real_headers := Map1 } = Msg,
    Map2 = maps:remove(CiName, Map1),
    Msg#{ real_headers := Map2 }.

-spec add_real_msg_headers(header_map(), message()) -> message().
add_real_msg_headers(ExtraMap, Msg) ->
    #{ real_headers := Map1 } = Msg,
    Map2 = maps:merge(Map1, ExtraMap),
    Msg#{ real_headers := Map2 }.

-spec list_pseudo_msg_header_names(message()) -> [binary()].
list_pseudo_msg_header_names(Msg) ->
    #{ pseudo_headers := Map } = Msg,
    maps:keys(Map).

-spec list_real_msg_header_names(message()) -> [binary()].
list_real_msg_header_names(Msg) ->
    #{ real_headers := Map } = Msg,
    maps:keys(Map).

-spec list_msg_headers(message()) -> header_list().
list_msg_headers(Msg) ->
    #{ pseudo_headers := MapA,
       real_headers := MapB } = Msg,
    Merged = maps:merge(MapB, MapA),
    maps:to_list(Merged).

-spec list_msg_header_names(message()) -> [binary()].
list_msg_header_names(Msg) ->
    #{ pseudo_headers := MapA,
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

-spec parse_authorization_header({ok, binary()} | error)
        -> {ok, params()} | {error, auth_parse_failure()}.
parse_authorization_header({ok, <<"Signature ", EncodedParams/binary>>}) ->
    decode_signature_auth_params(EncodedParams);
parse_authorization_header({ok, _OtherAuth}) ->
    {error, invalid_auth_type};
parse_authorization_header(error) ->
    {error, missing_authorization_header}.

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
    try
        base64:decode(EncodedSignature)
    catch
        _ -> error(invalid_header_param)
    end;
decode_signature_param_value(_Key, Value) ->
    Value.

-spec decode_signature_auth_params(binary()) -> {ok, params()} | {error, header_params_failure()}.
decode_signature_auth_params(Encoded) ->
    case backwater_http_header_params:decode(Encoded) of
        {ok, BinParams} ->
            try
                Params = maps:map(fun decode_signature_param_value/2, BinParams),
                {ok, Params}
            catch
                error:invalid_header_param ->
                    {error, invalid_header_params}
            end;
        error ->
            {error, invalid_header_params}
    end.

-spec validate_response_request_id(config(), message(), binary(), {ok, binary()} | error)
        -> message_validation_success() |
           {error, Reason :: response_validation_failure()}.
validate_response_request_id(Config, Msg, RequestId, {ok, RequestId}) ->
    SignatureHeaderLookup = find_real_msg_header(<<"signature">>, Msg),
    case parse_signature_header(SignatureHeaderLookup) of
        {ok, Params} ->
            validate_params(Config, Params, Msg);
        {error, Reason} ->
            {error, Reason}
    end;
validate_response_request_id(_Config, _Msg, _RequestId, {ok, _WrongRequestId}) ->
    {error, mismatched_request_id};
validate_response_request_id(_Config, _Msg, _RequestId, error) ->
    {error, missing_request_id}.

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
    Mandatory = list_pseudo_msg_header_names(Msg) ++ ?VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES,
    MissingMandatory =
        backwater_util:lists_anymap(
          fun (Name) ->
                  (not lists:member(Name, SignedHeaderNames))
                  andalso {true, Name}
          end,
          Mandatory),

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
validate_signature(Config, #{ <<"headers">> := SignedHeaderNames, <<"signature">> := Signature },
                   Msg) ->
    case build_signature_iodata(SignedHeaderNames, Msg) of
        {error, Reason} ->
            {error, Reason};
        {ok, IoData} ->
            #{ key := Key } = Config,
            ExpectedSignature = crypto:hmac(sha256, Key, IoData),
            case ExpectedSignature =:= Signature of
                false ->
                    {error, invalid_signature};
                true ->
                    {ok, RequestId} = find_real_msg_header(<<"x-request-id">>, Msg),
                    {ok, BodyDigest} = find_real_msg_header(<<"digest">>, Msg),
                    SignedMsg =
                        Msg#{ config => Config,
                              request_id => RequestId,
                              signed_header_names => SignedHeaderNames,
                              body_digest => BodyDigest },
                    {ok, SignedMsg}
            end
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Signing
%% ------------------------------------------------------------------

-spec generate_authorization_header_value(config(), message(), [binary()]) -> nonempty_binary().
generate_authorization_header_value(Config, Msg, SignedHeaderNames) ->
    EncodedParams = generate_signature_header_value(Config, Msg, SignedHeaderNames),
    ?OPAQUE_BINARY(<<"Signature ", EncodedParams/binary>>).

-spec generate_signature_header_value(config(), message(), [binary()]) -> binary().
generate_signature_header_value(Config, Msg, SignedHeaderNames) ->
    #{ key := Key } = Config,
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

%% ------------------------------------------------------------------
%% Internal Function Definitions - Unit Tests
%% ------------------------------------------------------------------
-ifdef(TEST).

test_config() ->
    config(crypto:strong_rand_bytes(32)).

test_request_msg() ->
    Config = test_config(),
    {Config, new_request_msg(<<"POST">>, <<"/path">>, #{})}.

test_signed_request_msg() ->
    {Config, RequestMsg} = test_request_msg(),
    RequestId = crypto:strong_rand_bytes(16),
    SignedRequestMsg = sign_request(Config, RequestMsg, <<"request body">>, RequestId),
    {Config, SignedRequestMsg}.

valid_response_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    ?assertMatch(
       {ok, #{} = _SignedResponseMsg},
       validate_response_signature(SignedRequestMsg, SignedResponseMsg)).

mismatched_request_id_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    CorruptSignedRequestMsg = SignedRequestMsg#{ request_id := crypto:strong_rand_bytes(16) },
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, CorruptSignedRequestMsg),
    ?assertMatch(
       {error, mismatched_request_id},
       validate_response_signature(SignedRequestMsg, SignedResponseMsg)).

missing_request_id_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    CorruptSignedResponseMsg = remove_real_msg_header(<<"x-request-id">>, SignedResponseMsg),
    ?assertMatch(
       {error, missing_request_id},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

missing_signature_header_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    CorruptSignedResponseMsg = remove_real_msg_header(<<"signature">>, SignedResponseMsg),
    ?assertMatch(
       {error, missing_signature_header},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

invalid_header_params_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    CorruptSignedResponseMsg =
        add_real_msg_headers(#{ <<"signature">> => <<"bla=ble;;;">> }, SignedResponseMsg),
    ?assertMatch(
       {error, invalid_header_params},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

unknown_key_id_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    CorruptSignedResponseMsg =
        add_real_msg_headers(#{ <<"signature">> => <<"keyId=\"unknown\"">> }, SignedResponseMsg),
    ?assertMatch(
       {error, unknown_key},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

unknown_algorithm_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    CorruptSignedResponseMsg =
        add_real_msg_headers(#{ <<"signature">> => <<"keyId=\"", ?KEY_ID/binary, "\","
                                                     "algorithm=\"unknown\"">>
                              },
                             SignedResponseMsg),
    ?assertMatch(
       {error, unknown_algorithm},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

missing_signed_header_list_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    CorruptSignedResponseMsg =
        add_real_msg_headers(#{ <<"signature">> => <<"keyId=\"", ?KEY_ID/binary, "\","
                                                     "algorithm=\"", ?ALGORITHM/binary, "\"">>
                              },
                             SignedResponseMsg),
    ?assertMatch(
       {error, missing_signed_header_list},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

missing_mandatory_pseudo_header_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    CorruptSignedResponseMsg =
        add_real_msg_headers(#{ <<"signature">> => <<"keyId=\"", ?KEY_ID/binary, "\","
                                                     "algorithm=\"", ?ALGORITHM/binary, "\",",
                                                     "headers=\"\"">>
                              },
                             SignedResponseMsg),

    MissingHeaderName = <<"(response-status)">>,
    ?assertMatch(
       {error, {missing_mandatory_header, MissingHeaderName}},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

missing_mandatory_real_header_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    CorruptSignedResponseMsg =
        add_real_msg_headers(#{ <<"signature">> => <<"keyId=\"", ?KEY_ID/binary, "\","
                                                     "algorithm=\"", ?ALGORITHM/binary, "\",",
                                                     "headers=\"(response-status)\"">>
                              },
                             SignedResponseMsg),

    MissingHeaderName = hd(?VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES),
    ?assertMatch(
       {error, {missing_mandatory_header, MissingHeaderName}},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

missing_mandatorily_signed_headers_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    EncodedSignatureHeaders =
        iolist_to_binary(
          lists:join(" ", (list_pseudo_msg_header_names(SignedResponseMsg) ++
                           ?VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES))),

    ExtraHeaderName = hd(?VALIDATION_MANDATORILY_SIGNED_HEADER_NAMES_IF_PRESENT),
    CorruptSignedResponseMsg =
        add_real_msg_headers(#{ <<"signature">> => <<"keyId=\"", ?KEY_ID/binary, "\","
                                                     "algorithm=\"", ?ALGORITHM/binary, "\",",
                                                     "headers=\"", EncodedSignatureHeaders/binary, "\"">>,
                                ExtraHeaderName => <<"blah">>
                              },
                             SignedResponseMsg),
    ?assertMatch(
       {error, {missing_mandatorily_signed_header, ExtraHeaderName}},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

missing_header_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{ <<"some_header">> => <<"bla">> }),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    CorruptSignedResponseMsg = remove_real_msg_header(<<"some_header">>, SignedResponseMsg),
    ?assertEqual(
       {error, {missing_header, <<"some_header">>}},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

invalid_signature_test() ->
    {Config, SignedRequestMsg} = test_signed_request_msg(),
    ResponseMsg = new_response_msg(200, #{}),
    SignedResponseMsg = sign_response(Config, ResponseMsg, <<"response body">>, SignedRequestMsg),
    CorruptSignedResponseMsg = add_real_msg_headers(#{ <<"digest">> => <<>> }, SignedResponseMsg),
    ?assertMatch(
       {error, invalid_signature},
       validate_response_signature(SignedRequestMsg, CorruptSignedResponseMsg)).

-endif.
