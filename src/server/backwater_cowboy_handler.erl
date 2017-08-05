-module(backwater_cowboy_handler).

-include("../backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([initial_state/1]).

%% ------------------------------------------------------------------
%% cowboy_http_handler Function Exports
%% ------------------------------------------------------------------

-export([init/2]).
-export([terminate/3]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CACHED_FUNCTION_PROPERTIES_TTL, (timer:seconds(5))).
-define(COMPRESSION_THRESHOLD, 300).
-define(KNOWN_CONTENT_ENCODINGS, [<<"gzip">>, <<"identity">>]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-opaque state() ::
        #{ authentication := backwater_server_instance:authentication(),
           decode_unsafe_terms := boolean(),
           return_exception_stacktraces := boolean(),
           exposed_modules := [backwater_module_info:exposed_module()],

           req => req(),
           version => backwater_module_info:version(),
           bin_module => binary(),
           bin_function => binary(),
           arity => arity(),

           signed_request_msg => backwater_http_signatures:signed_message(),

           function_properties => backwater_module_info:fun_properties(),
           args_content_type => content_type(),
           args_content_encoding => binary(),
           args => [term()],
           response => response(),
           accepted_result_content_types => [accepted_content_type()],
           accepted_result_content_encodings => [accepted_content_encoding()],
           result_content_type => content_type(),
           result_content_encoding => binary() }.
-export_type([state/0]).

-type content_type() :: {Type :: binary(), SubType :: binary(), content_type_params()}.
-type content_type_params() :: [{binary(), binary()}].

-type accepted_content_type() :: {content_type(), Quality :: 0..1000, accepted_ext()}.
-type accepted_ext() :: [{binary(), binary()} | binary()].

-type accepted_content_encoding() :: {content_type(), Quality :: 0..1000}.

-type req() :: cowboy_req:req().

-type http_status() :: cowboy:http_status().
-type http_headers() :: cowboy:http_headers().
-type response() ::
        #{ status_code := http_status(),
           headers := http_headers(),
           body := iodata() }.

-type call_result() ::
        ({success, term()} |
         {exception, Class :: term(), Exception :: term(), [erlang:stack_item()]}).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec initial_state(backwater_server_instance:config()) -> state().
initial_state(Config) ->
    #{ authentication => maps:get(authentication, Config),
       decode_unsafe_terms => maps:get(decode_unsafe_terms, Config, true),
       return_exception_stacktraces => maps:get(return_exception_stacktraces, Config, true),
       exposed_modules => maps:get(exposed_modules, Config, []) }.

%% ------------------------------------------------------------------
%% cowboy_http_handler Function Definitions
%% ------------------------------------------------------------------

-spec init(req(), state()) -> {ok, req(), state()}.
init(Req1, State1) ->
    %% initialize
    Version = cowboy_req:binding(version, Req1),
    BinModule = cowboy_req:binding(module, Req1),
    BinFunction = cowboy_req:binding(function, Req1),
    Arity = cowboy_req:binding(arity, Req1),
    State2 =
        State1#{ req => Req1,
                 version => Version,
                 bin_module => BinModule,
                 bin_function => BinFunction,
                 arity => Arity
               },

    State3 =
        execute_pipeline(
          [fun check_authentication/1,
           fun check_method/1,
           fun check_authorization/1,
           fun check_existence/1,
           fun check_args_content_type/1,
           fun check_args_content_encoding/1,
           fun check_accepted_result_content_types/1,
           fun check_accepted_result_content_encodings/1,
           fun negotiate_args_content_type/1,
           fun negotiate_args_content_encoding/1,
           fun negotiate_result_content_type/1,
           fun negotiate_result_content_encoding/1,
           fun read_and_decode_args/1,
           fun execute_call/1],
          State2),

    {Req2, State4} = maps:take(req, State3),
    {ok, Req2, State4}.

-spec terminate(term(), req(), state()) -> ok.
terminate({crash, Class, Reason}, _Req, _State) ->
    Stacktrace = erlang:get_stacktrace(),
    io:format("Crash! ~p:~p, ~p~n", [Class, Reason, Stacktrace]),
    ok;
terminate(_Reason, _Req, _State) ->
    ok.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Pipeline
%% ------------------------------------------------------------------

-spec execute_pipeline([fun ((state()) -> {continue | stop, state()}), ...], state())
        -> state().
execute_pipeline([Handler | NextHandlers], State1) ->
    case Handler(State1) of
        {continue, State2} ->
            execute_pipeline(NextHandlers, State2);
        {stop, State2} ->
            send_response(State2)
    end;
execute_pipeline([], State) ->
    send_response(State).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Authentication
%% ------------------------------------------------------------------

-spec check_authentication(state()) -> {continue | stop, state()}.
check_authentication(#{ req := Req, authentication := Authentication } = State) ->
    {signature, Key} = Authentication,
    SignaturesConfig = backwater_http_signatures:config(Key),

    Method = cowboy_req:method(Req),
    PathWithQs = req_path_with_qs(Req),
    Headers = cowboy_req:headers(Req),
    RequestMsg = backwater_http_signatures:new_request_msg(Method, PathWithQs, {ci_headers, Headers}),

    case backwater_http_signatures:validate_request_signature(SignaturesConfig, RequestMsg) of
        {ok, SignedRequestMsg} ->
            {continue, State#{ signed_request_msg => SignedRequestMsg }};
        {error, Reason} ->
            AuthChallengeHeaders =
                backwater_http_signatures:get_request_auth_challenge_headers(RequestMsg),
            {stop, set_response(401, AuthChallengeHeaders, Reason, State)}
    end.

-spec req_path_with_qs(req()) -> binary().
req_path_with_qs(Req) ->
    Path = cowboy_req:path(Req),
    case cowboy_req:qs(Req) of
        <<>> -> Path;
        QueryString -> <<Path/binary, "?", QueryString/binary>>
    end.

-spec safe_req_header(binary(), state()) -> undefined | binary() | no_return().
safe_req_header(CiName, #{ req := Req } = State) ->
    case cowboy_req:header(CiName, Req) of
        undefined -> undefined;
        Value ->
            assert_header_safety(CiName, State),
            Value
    end.

-spec safe_req_parse_header(binary(), state()) -> term() | no_return().
safe_req_parse_header(CiName, State) ->
    safe_req_parse_header(CiName, State, undefined).

-spec safe_req_parse_header(binary(), state(), term()) -> term() | no_return().
safe_req_parse_header(CiName, #{ req := Req } = State, Default) ->
    case cowboy_req:parse_header(CiName, Req) of
        undefined -> Default;
        Value ->
            assert_header_safety(CiName, State),
            Value
    end.

-spec assert_header_safety(binary(), state()) -> true | no_return().
assert_header_safety(CiName, #{ signed_request_msg := SignedRequestMsg }) ->
    backwater_http_signatures:is_header_signed_in_signed_msg(CiName, SignedRequestMsg)
    orelse error({using_unsafe_header, CiName}).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Method
%% ------------------------------------------------------------------

-spec check_method(state()) -> {continue | stop, state()}.
check_method(#{ req := Req } = State) ->
    case cowboy_req:method(Req) =:= <<"POST">> of
        true ->
            {continue, State};
        false ->
            {stop, set_bodyless_response(405, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Request Authorization
%% ------------------------------------------------------------------

-spec check_authorization(state()) -> {continue | stop, state()}.
check_authorization(State) ->
    #{ bin_module := BinModule,
       exposed_modules := ExposedModules } = State,

    SearchResult =
        lists:any(
          fun (ExposedModule) ->
                  ModuleName = backwater_module_info:exposed_module_name(ExposedModule),
                  BinModule =:= atom_to_binary(ModuleName, utf8)
          end,
          ExposedModules),

    case SearchResult of
        true -> {continue, State};
        false -> {stop, set_bodyless_response(403, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Resource Existence
%% ------------------------------------------------------------------

-spec check_existence(state()) -> {continue | stop, state()}.
check_existence(State) ->
    case find_function_properties(State) of
        {found, FunctionProperties} ->
            {continue, State#{ function_properties => FunctionProperties }};
        Error ->
            {stop, set_response(404, Error, State)}
    end.

-spec find_function_properties(state())
        -> {found, backwater_module_info:fun_properties()} | Error
             when Error :: (module_version_not_found |
                            function_not_exported |
                            module_not_found).
find_function_properties(State) ->
    #{ exposed_modules := ExposedModules,
       version := BinVersion,
       bin_module := BinModule,
       bin_function := BinFunction,
       arity := Arity } = State,

    CacheKey = {exposed_function_properties, BinModule, BinVersion, BinFunction, Arity},
    case backwater_cache:find(CacheKey) of
        {ok, FunctionProperties} ->
            {found, FunctionProperties};
        error ->
            InfoPerExposedModule = backwater_module_info:generate(ExposedModules),
            case maps:find(BinModule, InfoPerExposedModule) of
                {ok, #{ version := Version }} when Version =/= BinVersion ->
                    module_version_not_found;
                {ok, #{ exports := Exports }} ->
                    case maps:find({BinFunction, Arity}, Exports) of
                        {ok, FunctionProperties} ->
                            % let's only fill successful lookups so that we don't risk
                            % overloading the cache if attacked (the trade off is potentially
                            % much higher CPU usage)
                            backwater_cache:put(CacheKey, FunctionProperties, ?CACHED_FUNCTION_PROPERTIES_TTL),
                            {found, FunctionProperties};
                        error ->
                            function_not_exported
                    end;
                error ->
                    module_not_found
            end
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Arguments Content Type
%% ------------------------------------------------------------------

-spec check_args_content_type(state()) -> {continue | stop, state()}.
check_args_content_type(State) ->
    case safe_req_parse_header(<<"content-type">>, State) of
        {_, _, _} = ContentType ->
            State2 = State#{ args_content_type => ContentType },
            {continue, State2};
        undefined ->
            {stop, set_response(400, {bad_header, 'content-type'}, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Arguments Content Encoding
%% ------------------------------------------------------------------

-spec check_args_content_encoding(state()) -> {continue, state()}.
check_args_content_encoding(State) ->
    case safe_req_header(<<"content-encoding">>, State) of
        <<ContentEncoding/binary>> ->
            State2 = State#{ args_content_encoding => ContentEncoding },
            {continue, State2};
        undefined ->
            State2 = State#{ args_content_encoding => <<"identity">> },
            {continue, State2}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Accepted Content Types
%% ------------------------------------------------------------------

-spec check_accepted_result_content_types(state()) -> {continue, state()}.
check_accepted_result_content_types(State) ->
    AcceptedContentTypes = safe_req_parse_header(<<"accept">>, State, []),
    SortedAcceptedContentTypes = lists:reverse( lists:keysort(2, AcceptedContentTypes) ),
    State2 = State#{ accepted_result_content_types => SortedAcceptedContentTypes },
    {continue, State2}.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Accepted Content Encodings
%% ------------------------------------------------------------------

-spec check_accepted_result_content_encodings(state()) -> {continue, state()}.
check_accepted_result_content_encodings(State) ->
    AcceptedContentEncodings = safe_req_parse_header(<<"accept-encoding">>, State, []),
    SortedAcceptedContentEncodings = lists:reverse( lists:keysort(2, AcceptedContentEncodings) ),
    State2 = State#{ accepted_result_content_encodings => SortedAcceptedContentEncodings },
    {continue, State2}.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Negotiate Arguments Content Type
%% ------------------------------------------------------------------

-spec negotiate_args_content_type(state()) -> {continue | stop, state()}.
negotiate_args_content_type(State) ->
    #{ function_properties := FunctionProperties,
       args_content_type := ArgsContentType } = State,
    #{ known_content_types := KnownContentTypes } = FunctionProperties,

    {Type, SubType, _ContentTypeParams} = ArgsContentType,
    SearchResult = lists:member({Type, SubType}, KnownContentTypes),

    case SearchResult of
        true ->
            {continue, State};
        false ->
            {stop, set_response(415, unsupported_content_type, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Negotiate Arguments Content Encoding
%% ------------------------------------------------------------------

-spec negotiate_args_content_encoding(state()) -> {continue | stop, state()}.
negotiate_args_content_encoding(State) ->
    #{ args_content_encoding := ArgsContentEncoding } = State,
    case lists:member(ArgsContentEncoding, ?KNOWN_CONTENT_ENCODINGS) of
        true ->
            {continue, State};
        false ->
            {stop, set_response(415, unsupported_content_encoding, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Negotiate Result Content Type
%% ------------------------------------------------------------------

-spec negotiate_result_content_type(state()) -> {continue | stop, state()}.
negotiate_result_content_type(State) ->
    #{ function_properties := FunctionProperties,
       accepted_result_content_types := AcceptedContentTypes } = State,
    #{ known_content_types := KnownContentTypes } = FunctionProperties,

    SearchResult =
        backwater_util:lists_anymap(
          fun ({{Type, SubType, _Params} = ContentType, _Quality, _AcceptExt}) ->
                  (lists:member({Type, SubType}, KnownContentTypes)
                   andalso {true, ContentType})
          end,
          AcceptedContentTypes),

    case SearchResult of
        {true, ContentType} ->
            State2 = State#{ result_content_type => ContentType },
            {continue, State2};
        false ->
            {stop, set_bodyless_response(406, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Negotiate Result Content Encoding
%% ------------------------------------------------------------------

-spec negotiate_result_content_encoding(state()) -> {continue | stop, state()}.
negotiate_result_content_encoding(State) ->
    #{ accepted_result_content_encodings := AcceptedContentEncodings } = State,

    SearchResult =
        backwater_util:lists_anymap(
          fun ({Encoding, _Params}) ->
                  (lists:member(Encoding, ?KNOWN_CONTENT_ENCODINGS)
                   andalso {true, Encoding})
          end,
          AcceptedContentEncodings),

    case SearchResult of
        {true, ContentEncoding} ->
            State2 = State#{ result_content_encoding => ContentEncoding },
            {continue, State2};
        false ->
            State2 = State#{ result_content_encoding => <<"identity">> },
            {continue, State2}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Read and Decode Arguments
%% ------------------------------------------------------------------

-spec read_and_decode_args(state()) -> {continue | stop, state()}.
read_and_decode_args(#{ req := Req } = State) ->
    case cowboy_req:read_body(Req) of
        {ok, Data, Req2} ->
            State2 = State#{ req := Req2 },
            validate_body_digest(Data, State2);
        {more, _Data, Req2} ->
            State2 = State#{ req := Req2 },
            {stop, set_bodyless_response(413, State2)}
    end.

validate_body_digest(Data, State) ->
    #{ signed_request_msg := SignedRequestMsg } = State,
    case backwater_http_signatures:validate_signed_msg_body(SignedRequestMsg, Data) of
        true -> decode_args_content_encoding(Data, State);
        false ->
            AuthChallengeHeaders =
                backwater_http_signatures:get_request_auth_challenge_headers(SignedRequestMsg),
            {stop, set_response(401, AuthChallengeHeaders, wrong_body_digest, State)}
    end.

-spec decode_args_content_encoding(binary(), state()) -> {continue | stop, state()}.
decode_args_content_encoding(Data, #{ args_content_encoding := <<"identity">> } = State) ->
    decode_args_content_type(Data, State);
decode_args_content_encoding(Data, #{ args_content_encoding := <<"gzip">> } = State) ->
    case backwater_encoding_gzip:decode(Data) of
        {ok, UncompressedData} ->
            decode_args_content_type(UncompressedData, State);
        {error, _} ->
            {stop, set_response(400, unable_to_uncompress_body, State)}
    end.

-spec decode_args_content_type(binary(), state()) -> {continue | stop, state()}.
decode_args_content_type(Data, State) ->
    #{ args_content_type := ArgsContentType } = State,
    case ArgsContentType of
        {<<"application">>, <<"x-erlang-etf">>, _Params} ->
            decode_etf_args(Data, State)
    end.

-spec decode_etf_args(binary(), state()) -> {continue | stop, state()}.
decode_etf_args(Data, State) ->
    #{ decode_unsafe_terms := DecodeUnsafeTerms } = State,
    case backwater_media_etf:decode(Data, DecodeUnsafeTerms) of
        error ->
            {stop, set_response(400, unable_to_decode_arguments, State)};
        {ok, UnvalidatedArgs} ->
            validate_args(UnvalidatedArgs, State)
    end.

-spec validate_args(term(), state()) -> {continue | stop, state()}.
validate_args(UnvalidatedArgs, State)
  when not is_list(UnvalidatedArgs) ->
    {stop, set_response(400, arguments_not_a_list, State)};
validate_args(UnvalidatedArgs, #{ arity := Arity } = State)
  when length(UnvalidatedArgs) =/= Arity ->
    {stop, set_response(400, inconsistent_arguments_arity, State)};
validate_args(Args, State) ->
    {continue, State#{ args => Args }}.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Execute Call
%% ------------------------------------------------------------------

-spec execute_call(state()) -> {continue, state()}.
execute_call(State) ->
    Result = call_function(State),
    {continue, set_response(200, Result, State)}.

-spec call_function(state()) -> call_result().
call_function(#{ function_properties := #{ function_ref := FunctionRef },
                 args := Args,
                 return_exception_stacktraces := ReturnExceptionStacktraces }) ->
    try
        {success, apply(FunctionRef, Args)}
    catch
        Class:Exception when ReturnExceptionStacktraces ->
            Stacktrace = erlang:get_stacktrace(),
            % Hide all calls previous to the one made to the target function (cowboy stuff, etc.)
            % This works under the assumption that *no sensible call* would ever go through the
            % current function again.
            PurgedStacktrace = backwater_util:purge_stacktrace_below({?MODULE,call_function,1}, Stacktrace),
            {exception, Class, Exception, PurgedStacktrace};
        Class:Exception ->
            {exception, Class, Exception, []}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Send Response
%% ------------------------------------------------------------------

-spec send_response(state()) -> state().
send_response(#{ signed_request_msg := SignedRequestMsg } = State1) ->
    % signed response
    #{ req := Req1, response := Response } = State1,
    #{ status_code := ResponseStatusCode, headers := ResponseHeaders1, body := ResponseBody } = Response,

    #{ authentication := {signature, Key} } = State1,
    Config = backwater_http_signatures:config(Key),
    ResponseMsg =
        backwater_http_signatures:new_response_msg(ResponseStatusCode, {ci_headers, ResponseHeaders1}),
    SignedResponseMsg =
        backwater_http_signatures:sign_response(Config, ResponseMsg, ResponseBody, SignedRequestMsg),
    ResponseHeaders2 = backwater_http_signatures:get_real_msg_headers(SignedResponseMsg),

    Req2 = cowboy_req:reply(ResponseStatusCode, ResponseHeaders2, ResponseBody, Req1),
    State1#{ req := Req2 };
send_response(State1) ->
    % unsigned response
    #{ req := Req1, response := Response } = State1,
    #{ status_code := ResponseStatusCode, headers := ResponseHeaders, body := ResponseBody } = Response,
    Req2 = cowboy_req:reply(ResponseStatusCode, ResponseHeaders, ResponseBody, Req1),
    State1#{ req := Req2 }.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Set Response
%% ------------------------------------------------------------------

-spec set_bodyless_response(http_status(), state()) -> state().
set_bodyless_response(StatusCode, State) ->
    Response = encode_response(StatusCode, nocache_headers(), <<>>, State),
    maps:put(response, Response, State).

-spec set_response(http_status(), term(), state()) -> state().
set_response(StatusCode, Value, State) ->
    set_response(StatusCode, #{}, Value, State).

-spec set_response(http_status(), http_headers(), term(), state()) -> state().
set_response(StatusCode, BaseHeaders, Value, #{ result_content_type := ResultContentType } = State) ->
    {Type, SubType, _Params} = ResultContentType,
    ContentTypeHeaders = #{ <<"content-type">> => [Type, "/", SubType] },
    Headers = backwater_util:maps_merge([nocache_headers(), BaseHeaders, ContentTypeHeaders]),
    Body =
        case {Type, SubType} of
            {<<"application">>, <<"x-erlang-etf">>} ->
                backwater_media_etf:encode(Value)
        end,
    Response = encode_response(StatusCode, Headers, Body, State),
    maps:put(response, Response, State);
set_response(StatusCode, BaseHeaders, Value, State) ->
    Headers = maps:merge(nocache_headers(), BaseHeaders),
    Body = iolist_to_binary(io_lib:format("~p", [Value])),
    Response = encode_response(StatusCode, Headers, Body, State),
    maps:put(response, Response, State).

-spec encode_response(http_status(), http_headers(), binary(), state()) -> response().
encode_response(StatusCode, Headers1, Body1, #{ result_content_encoding := <<"gzip">> })
  when byte_size(Body1) >= ?COMPRESSION_THRESHOLD ->
    Body2 = backwater_encoding_gzip:encode(Body1),
    Headers2 = Headers1#{ <<"content-encoding">> => <<"gzip">> },
    #{ status_code => StatusCode, headers => Headers2, body => Body2 };
encode_response(StatusCode, Headers, Body, _State) ->
    #{ status_code => StatusCode, headers => Headers, body => Body }.

-spec nocache_headers() -> http_headers().
nocache_headers() ->
    #{ <<"cache-control">> => <<"private, no-cache, no-store, must-revalidate">>,
       <<"pragma">> => <<"no-cache">>,
       <<"expires">> => <<"0">> }.
