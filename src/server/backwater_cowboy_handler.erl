-module(backwater_cowboy_handler).

-include("../backwater_common.hrl").

%% ------------------------------------------------------------------
%% cowboy_http_handler Function Exports
%% ------------------------------------------------------------------

-export([init/2]).
-export([terminate/3]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(MODULE_INFO_TTL, (timer:seconds(5))).

%% ------------------------------------------------------------------
%% Type exports
%% ------------------------------------------------------------------

-export_type([backwater_opts/0]).
-export_type([backwater_cowboy_opts/0]).
-export_type([backwater_cowboy_transport/0]).
-export_type([backwater_transport_opts/0]).
-export_type([backwater_protocol_opts/0]).
-export_type([access_conf/0]).
-export_type([username/0]).
-export_type([password/0]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type state() ::
        #{ req := req(),
           backwater_opts := backwater_opts(),
           version => backwater_module_info:version(),
           bin_module => binary(),
           bin_function => binary(),
           arity => arity(),
           access_conf => access_conf(),
           module_info => backwater_module_info:module_info(),
           function_properties => backwater_module_info:fun_properties(),
           args_content_type => content_type(),
           args_content_encoding => binary(),
           args => [term()],
           response => response(),
           accepted_result_content_types => [accepted_content_type()],
           result_content_type => content_type() }.


-type backwater_opts() ::
        #{ cowboy => backwater_cowboy_opts(),
           unauthenticated_access => access_conf(),
           authenticated_access => #{ username() => access_conf() } }.

-type backwater_cowboy_opts() ::
        #{ transport => backwater_cowboy_transport(),
           transport_options => backwater_transport_opts(),
           protocol_options => backwater_protocol_opts() }.

-type backwater_cowboy_transport() ::
        clear | tls |
        tcp | ssl |    % aliases #1
        http | https.  % aliases #2


-type backwater_transport_opts() :: ranch_tcp:opts() | ranch_ssl:opts().

-type backwater_protocol_opts() :: cowboy_protocol:opts().

-type access_conf() ::
        #{ decode_unsafe_terms := boolean(),
           exposed_modules := [backwater_module_info:exposed_module()],
           return_exception_stacktraces := boolean(),
           authentication => {basic, password()} }.

-type username() :: binary().
-type password() :: binary().


-type content_type() :: {Type :: binary(), SubType :: binary(), content_type_params()}.
-type content_type_params() :: [{binary(), binary()}].

-type accepted_content_type() :: {content_type(), Quality :: 0..1000, accepted_ext()}.
-type accepted_ext() :: [{binary(), binary()} | binary()].

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
%% cowboy_http_handler Function Definitions
%% ------------------------------------------------------------------

-spec init(req(), [backwater_opts(), ...]) -> {ok, req(), state()}.
init(Req1, [BackwaterOpts]) ->
    %% initialize
    Version = cowboy_req:binding(version, Req1),
    BinModule = cowboy_req:binding(module, Req1),
    BinFunction = cowboy_req:binding(function, Req1),
    Arity = cowboy_req:binding(arity, Req1),
    State1 = #{ req => Req1,
                backwater_opts => BackwaterOpts,
                version => Version,
                bin_module => BinModule,
                bin_function => BinFunction,
                arity => Arity
             },

    State2 =
        execute_pipeline(
          [fun check_method/1,
           fun check_authentication/1,
           fun check_authorization/1,
           fun check_existence/1,
           fun check_args_content_type/1,
           fun check_args_content_encoding/1,
           fun check_accepted_result_content_types/1,
           fun negotiate_args_content_type/1,
           fun negotiate_args_content_encoding/1,
           fun negotiate_result_content_type/1,
           fun read_and_decode_args/1,
           fun execute_call/1],
          State1),

    {Req2, State3} = maps:take(req, State2),
    {ok, Req2, State3}.

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
%% Internal Function Definitions - Check Method
%% ------------------------------------------------------------------

-spec check_method(state()) -> {continue | stop, state()}.
check_method(#{ req := Req } = State) ->
    case cowboy_req:method(Req) =:= <<"POST">> of
        true ->
            {continue, State};
        false ->
            {stop, bodyless_response(405, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Authentication
%% ------------------------------------------------------------------

-spec check_authentication(state()) -> {continue | stop, state()}.
check_authentication(#{ req := Req } = State) ->
    ParseResult = cowboy_req:parse_header(<<"authorization">>, Req),
    case handle_parsed_authentication(ParseResult, State) of
        {valid, AccessConf} ->
            {continue, State#{ access_conf => AccessConf }};
        invalid ->
            {stop, bodyless_response(401, failed_auth_prompt_headers(), State)}
    end.

-spec handle_parsed_authentication(ParseResult, state())
        -> {valid, access_conf()} | invalid
             when ParseResult :: Valid | Invalid,
                  Valid :: {basic, username(), password()},
                  Invalid :: tuple() | undefined.
handle_parsed_authentication({basic, Username, Password}, State) ->
    #{ backwater_opts := BackwaterOpts } = State,
    AuthenticatedAccessConfs = maps:get(authenticated_access, BackwaterOpts, #{}),
    AuthenticatedAccessConfLookup = maps:find(Username, AuthenticatedAccessConfs),
    validate_authentication(AuthenticatedAccessConfLookup, Password);
handle_parsed_authentication(undefined, State) ->
    #{ backwater_opts := BackwaterOpts } = State,
    ExplicitAccessConf = maps:get(unauthenticated_access, BackwaterOpts, #{}),
    DefaultAccessConf = default_access_conf(unauthenticated_access),
    AccessConf = maps:merge(DefaultAccessConf, ExplicitAccessConf),
    {valid, AccessConf};
handle_parsed_authentication(ParseResult, _State) when is_tuple(ParseResult) ->
    % other authentication method
    invalid.

-spec validate_authentication(AuthenticatedAccessConfLookup :: {ok, access_conf()} | error,
                              GivenPassword :: password())
        -> {valid, access_conf()} | invalid.
validate_authentication({ok, #{ authentication := {basic, Password} } = ExplicitAccessConf},
                        GivenPassword)
  when Password =:= GivenPassword ->
    DefaultAccessConf = default_access_conf(authenticated_access),
    AccessConf = maps:merge(DefaultAccessConf, ExplicitAccessConf),
    {valid, AccessConf};
validate_authentication({ok, #{ authentication := {basic, _Password} }},
                        _GivenPassword) ->
    % wrong password
    invalid;
validate_authentication(error, _GivenPassword) ->
    % username not found
    invalid.

%-spec default_access_conf(unauthenticated_access | authenticated_access) -> access_conf().
default_access_conf(unauthenticated_access) ->
    #{ decode_unsafe_terms => false,
       exposed_modules => [],
       return_exception_stacktraces => false };
default_access_conf(authenticated_access) ->
    #{ decode_unsafe_terms => true,
       exposed_modules => [],
       return_exception_stacktraces => true }.

%-spec failed_auth_prompt_header() -> {nonempty_binary(), nonempty_binary()}.
failed_auth_prompt_headers() ->
    #{ <<"www-authenticate">> => <<"Basic realm=\"backwater\"">> }.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Request Authorization
%% ------------------------------------------------------------------

-spec check_authorization(state()) -> {continue | stop, state()}.
check_authorization(State) ->
    #{ bin_module := BinModule,
       access_conf := AccessConf } = State,
    #{ exposed_modules := ExposedModules } = AccessConf,

    SearchResult =
        lists:any(
          fun (ExposedModule) ->
                  ModuleName = backwater_module_info:exposed_module_name(ExposedModule),
                  BinModule =:= atom_to_binary(ModuleName, utf8)
          end,
          ExposedModules),

    case SearchResult of
        true -> {continue, State};
        false -> {stop, bodyless_response(403, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Resource Existence
%% ------------------------------------------------------------------

-spec check_existence(state()) -> {continue | stop, state()}.
check_existence(State) ->
    case find_resource(State) of
        {found, State2} ->
            {continue, State2};
        Error ->
            {stop, response(404, Error, State)}
    end.

-spec find_resource(state())
        -> {found, state()} | Error
             when Error :: (module_version_not_found |
                            function_not_exported |
                            module_not_found).
find_resource(State) ->
    #{ access_conf := AccessConf,
       version := BinVersion,
       bin_module := BinModule,
       bin_function := BinFunction,
       arity := Arity } = State,
    #{ exposed_modules := ExposedModules } = AccessConf,

    CacheKey = {exposed_modules, erlang:phash2(ExposedModules)},
    InfoPerExposedModule =
        case backwater_cache:find(CacheKey) of
            {ok, Cached} ->
                Cached;
            error ->
                Info = backwater_module_info:generate(ExposedModules),
                backwater_cache:put(CacheKey, Info, ?MODULE_INFO_TTL),
                Info
        end,

    case maps:find(BinModule, InfoPerExposedModule) of
        {ok, #{ version := Version }} when Version =/= BinVersion ->
            module_version_not_found;
        {ok, #{ exports := Exports } = ModuleInfo} ->
            case maps:find({BinFunction, Arity}, Exports) of
                {ok, Resource} ->
                    State2 = State#{ module_info => ModuleInfo, function_properties => Resource },
                    {found, State2};
                error ->
                    function_not_exported
            end;
        error ->
            module_not_found
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Arguments Content Type
%% ------------------------------------------------------------------

-spec check_args_content_type(state()) -> {continue | stop, state()}.
check_args_content_type(#{ req := Req } = State) ->
    case cowboy_req:parse_header(<<"content-type">>, Req) of
        {_, _, _} = ContentType ->
            State2 = State#{ args_content_type => ContentType },
            {continue, State2};
        undefined ->
            {stop, response(400, {bad_header, 'content-type'}, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Arguments Content Encoding
%% ------------------------------------------------------------------

-spec check_args_content_encoding(state()) -> {continue, state()}.
check_args_content_encoding(#{ req := Req} = State) ->
    case cowboy_req:header(<<"content-encoding">>, Req) of
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
check_accepted_result_content_types(#{ req := Req } = State) ->
    AcceptedContentTypes = cowboy_req:parse_header(<<"accept">>, Req, []),
    SortedAcceptedContentTypes = lists:reverse( lists:keysort(2, AcceptedContentTypes) ),
    State2 = State#{ accepted_result_content_types => SortedAcceptedContentTypes },
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
            {stop, response(415, unsupported_content_type, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Negotiate Arguments Content Encoding
%% ------------------------------------------------------------------

-spec negotiate_args_content_encoding(state()) -> {continue | stop, state()}.
negotiate_args_content_encoding(State) ->
    #{ args_content_encoding := ArgsContentEncoding } = State,
    case lists:member(ArgsContentEncoding, [<<"identity">>, <<"gzip">>]) of
        true ->
            {continue, State};
        false ->
            {stop, response(415, unsupported_content_encoding, State)}
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
            {stop, bodyless_response(406, State)}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Read and Decode Arguments
%% ------------------------------------------------------------------

-spec read_and_decode_args(state()) -> {continue | stop, state()}.
read_and_decode_args(#{ req := Req } = State) ->
    case cowboy_req:read_body(Req) of
        {ok, Data, Req2} ->
            State2 = State#{ req := Req2 },
            decode_args_content_encoding(Data, State2);
        {more, _Data, Req2} ->
            State2 = State#{ req := Req2 },
            {stop, bodyless_response(413, State2)}
    end.

-spec decode_args_content_encoding(binary(), state()) -> {continue | stop, state()}.
decode_args_content_encoding(Data, #{ args_content_encoding := <<"identity">> } = State) ->
    decode_args_content_type(Data, State);
decode_args_content_encoding(Data, #{ args_content_encoding := <<"gzip">> } = State) ->
    case backwater_encoding_gzip:decode(Data) of
        {ok, UncompressedData} ->
            decode_args_content_type(UncompressedData, State);
        {error, _} ->
            {stop, response(400, unable_to_uncompress_body, State)}
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
    #{ access_conf := AccessConf } = State,
    #{ decode_unsafe_terms := DecodeUnsafeTerms } = AccessConf,
    case backwater_media_etf:decode(Data, DecodeUnsafeTerms) of
        error ->
            {stop, response(400, unable_to_decode_arguments, State)};
        {ok, UnvalidatedArgs} ->
            validate_args(UnvalidatedArgs, State)
    end.

-spec validate_args(term(), state()) -> {continue | stop, state()}.
validate_args(UnvalidatedArgs, State)
  when not is_list(UnvalidatedArgs) ->
    {stop, response(400, arguments_not_a_list, State)};
validate_args(UnvalidatedArgs, #{ arity := Arity } = State)
  when length(UnvalidatedArgs) =/= Arity ->
    {stop, response(400, inconsistent_arguments_arity, State)};
validate_args(Args, State) ->
    %handle_call(Args, Req, State).
    {continue, State#{ args => Args }}.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Execute Call
%% ------------------------------------------------------------------

-spec execute_call(state()) -> {continue, state()}.
execute_call(State) ->
    #{ access_conf := AccessConf,
       function_properties := FunctionProperties,
       args := Args } = State,
    #{ function_ref := FunctionRef } = FunctionProperties,
    Result = call_function(FunctionRef, Args, AccessConf),
    {continue, response(200, Result, State)}.

-spec call_function(fun(), [term()], access_conf()) -> call_result().
call_function(MF, Args, #{ return_exception_stacktraces := ReturnExceptionStacktraces }) ->
    try
        {success, apply(MF, Args)}
    catch
        Class:Exception when ReturnExceptionStacktraces ->
            Stacktrace = erlang:get_stacktrace(),
            % Hide all calls previous to the one made to the target function (cowboy stuff, etc.)
            % This works under the assumption that *no sensible call* would ever go through the
            % current function again.
            PurgedStacktrace = backwater_util:purge_stacktrace_below({?MODULE,call_function,3}, Stacktrace),
            {exception, Class, Exception, PurgedStacktrace};
        Class:Exception ->
            {exception, Class, Exception, []}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Send Response
%% ------------------------------------------------------------------

-spec send_response(state()) -> state().
send_response(State1) ->
    #{ req := Req1, response := Response } = State1,
    #{ status_code := ResponseStatusCode, headers := ResponseHeaders, body := ResponseBody } = Response,
    Req2 = cowboy_req:reply(ResponseStatusCode, ResponseHeaders, ResponseBody, Req1),
    State1#{ req := Req2 }.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Set Response
%% ------------------------------------------------------------------

-spec bodyless_response(http_status(), state()) -> state().
bodyless_response(StatusCode, State) ->
    Response = #{ status_code => StatusCode, headers => nocache_headers(), body => <<>> },
    maps:put(response, Response, State).

-spec bodyless_response(http_status(), http_headers(), state()) -> state().
bodyless_response(StatusCode, BaseHeaders, State) ->
    Headers = maps:merge(nocache_headers(), BaseHeaders),
    Response = #{ status_code => StatusCode, headers => Headers, body => <<>> },
    maps:put(response, Response, State).

-spec response(http_status(), term(), state()) -> state().
response(StatusCode, Value, State) ->
    response(StatusCode, #{}, Value, State).

-spec response(http_status(), http_headers(), term(), state()) -> state().
response(StatusCode, BaseHeaders, Value, #{ result_content_type := ResultContentType } = State) ->
    {Type, SubType, _Params} = ResultContentType,
    ContentTypeHeaders = #{ <<"content-type">> => [Type, "/", SubType] },
    Headers = backwater_util:maps_merge([nocache_headers(), BaseHeaders, ContentTypeHeaders]),
    Body =
        case {Type, SubType} of
            {<<"application">>, <<"x-erlang-etf">>} ->
                backwater_media_etf:encode(Value)
        end,
    Response = #{ status_code => StatusCode, headers => Headers, body => Body },
    maps:put(response, Response, State);
response(StatusCode, BaseHeaders, Value, State) ->
    Headers = maps:merge(nocache_headers(), BaseHeaders),
    Body = io_lib:format("~p", [Value]),
    Response = #{ status_code => StatusCode, headers => Headers, body => Body },
    maps:put(response, Response, State).

-spec nocache_headers() -> http_headers().
nocache_headers() ->
    #{ <<"cache-control">> => <<"private, no-cache, no-store, must-revalidate">>,
       <<"pragma">> => <<"no-cache">>,
       <<"expires">> => <<"0">> }.
