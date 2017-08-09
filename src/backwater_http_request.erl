-module(backwater_http_request).

-include_lib("hackney/include/hackney_lib.hrl").
-include("backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode/6]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(COMPRESSION_THRESHOLD, 300). % bytes

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type nonempty_headers() :: [{nonempty_binary(), binary()}, ...].
-export_type([nonempty_headers/0]).

-type state() :: #{ signed_request_msg := backwater_http_signatures:signed_message() }.
-export_type([state/0]).

-type t() :: {Method :: nonempty_binary(), Url :: nonempty_binary(),
              Headers :: nonempty_headers(), Body :: binary()}.
-export_type([t/0]).

-type stateful_request() :: {t(), state()}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec encode(Endpoint, Version, Module, Function, Args, Secret) -> {Request, RequestState}
            when Endpoint :: nonempty_binary(),
                 Version :: unicode:chardata(),
                 Module :: module(),
                 Function :: atom(),
                 Args :: [term()],
                 Secret :: binary(),
                 Request :: t(),
                 RequestState :: state().

encode(Endpoint, Version, Module, Function, Args, Secret) ->
    Body = backwater_media_etf:encode(Args),
    Arity = length(Args),
    Method = ?OPAQUE_BINARY(<<"POST">>),
    Url = request_url(Endpoint, Version, Module, Function, Arity),
    MediaType = ?OPAQUE_BINARY(<<"application/x-erlang-etf">>),
    Headers =
        [{?OPAQUE_BINARY(<<"accept">>), ?OPAQUE_BINARY(<<MediaType/binary>>)},
         {?OPAQUE_BINARY(<<"accept-encoding">>), ?OPAQUE_BINARY(<<"gzip">>)},
         {?OPAQUE_BINARY(<<"content-type">>), ?OPAQUE_BINARY(<<MediaType/binary>>)}],
    compress(Method, Url, Headers, Body, Secret).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec request_url(nonempty_binary(), unicode:chardata(), module(), atom(), arity())
        -> nonempty_binary().
request_url(Endpoint, Version, Module, Function, Arity) ->
    PathComponents =
        [hackney_url:urlencode(unicode:characters_to_binary(Version)),
         hackney_url:urlencode(atom_to_binary(Module, utf8)),
         hackney_url:urlencode(atom_to_binary(Function, utf8)),
         integer_to_binary(Arity)],
    QueryString = <<>>,
    hackney_url:make_url(Endpoint, PathComponents, QueryString).

-spec compress(nonempty_binary(), nonempty_binary(), nonempty_headers(), binary(), binary())
        -> stateful_request().
compress(Method, Url, Headers, Body, Secret)
  when byte_size(Body) > ?COMPRESSION_THRESHOLD ->
    CompressedBody = backwater_encoding_gzip:encode(Body),
    UpdatedHeaders = [{<<"content-encoding">>, <<"gzip">>} | Headers],
    authenticate(Method, Url, UpdatedHeaders, CompressedBody, Secret);
compress(Method, Url, Headers, Body, Secret) ->
    authenticate(Method, Url, Headers, Body, Secret).

-spec authenticate(nonempty_binary(), nonempty_binary(), nonempty_headers(), binary(), binary())
        -> stateful_request().
authenticate(Method, Url, Headers1, Body, Secret) ->
    EncodedPathWithQs = url_encoded_path_with_qs(Url),
    SignaturesConfig = backwater_http_signatures:config(Secret),
    RequestMsg = backwater_http_signatures:new_request_msg(Method, EncodedPathWithQs, Headers1),
    RequestId = base64:encode( crypto:strong_rand_bytes(16) ),
    SignedRequestMsg = backwater_http_signatures:sign_request(SignaturesConfig, RequestMsg, Body, RequestId),
    Headers2 = backwater_http_signatures:list_real_msg_headers(SignedRequestMsg),
    Request = {?OPAQUE_BINARY(Method), ?OPAQUE_BINARY(Url), Headers2, Body},
    State = #{ signed_request_msg => SignedRequestMsg },
    {Request, State}.

-spec url_encoded_path_with_qs(nonempty_binary()) -> binary().
url_encoded_path_with_qs(Url) ->
    HackneyUrl = hackney_url:parse_url(Url),
    #hackney_url{ path = Path, qs = QueryString } = HackneyUrl,
    EncodedPath  = hackney_url:pathencode(Path),
    <<EncodedPath/binary, QueryString/binary>>.
