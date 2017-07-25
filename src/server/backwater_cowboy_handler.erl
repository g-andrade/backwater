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
        #{ backwater_opts := backwater_opts(),
           unvalidated_version := binary(),
           unvalidated_module := binary(),
           unvalidated_function := binary(),
           unvalidated_arity := binary(),
           access_conf => access_conf(),
           version => backwater_module_info:version(),
           bin_module => binary(),
           bin_function => binary(),
           %module => module(),
           %function => atom(),
           arity => arity(),
           module_info => backwater_module_info:module_info(),
           function_properties => backwater_module_info:fun_properties(),
           args_content_type => content_type(),
           args_content_encoding => binary(),
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
           headers => http_headers(),
           body => iodata() }.

-type call_result() ::
        ({success, term()} |
         {exception, Class :: term(), Exception :: term(), [erlang:stack_item()]}).

%% ------------------------------------------------------------------
%% cowboy_http_handler Function Definitions
%% ------------------------------------------------------------------

-spec init(req(), [backwater_opts(), ...]) -> {ok, req(), state()}.
init(Req, [BackwaterOpts]) ->
    %% initialize
    UnvalidatedVersion = cowboy_req:binding(version, Req),
    UnvalidatedModule = cowboy_req:binding(module, Req),
    UnvalidatedFunction = cowboy_req:binding(function, Req),
    UnvalidatedArity = cowboy_req:binding(arity, Req),
    State1 = #{ backwater_opts => BackwaterOpts,
               unvalidated_version => UnvalidatedVersion,
               unvalidated_module => UnvalidatedModule,
               unvalidated_function => UnvalidatedFunction,
               unvalidated_arity => UnvalidatedArity
             },

    %% handle request
    {Response, Req2, State2} = handle_method(Req, State1),

    %% reply
    StatusCode = maps:get(status_code, Response),
    ResponseHeaders = maps:get(headers, Response, []),
    ResponseBody = maps:get(body, Response, <<>>),
    ResponseHeadersWithNoCache = maps:merge(nocache_headers(), ResponseHeaders),
    Req3 = cowboy_req:reply(StatusCode, ResponseHeadersWithNoCache, ResponseBody, Req2),
    {ok, Req3, State2}.

-spec terminate(term(), req(), state()) -> ok.
terminate({crash, Class, Reason}, _Req, _State) ->
    Stacktrace = erlang:get_stacktrace(),
    io:format("Crash! ~p:~p, ~p~n", [Class, Reason, Stacktrace]),
    ok;
terminate(_Reason, _Req, _State) ->
    ok.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Method
%% ------------------------------------------------------------------

-spec handle_method(req(), state()) -> {response(), req(), state()}.
handle_method(Req, State) ->
    case cowboy_req:method(Req) =:= <<"POST">> of
        true ->
            check_authentication(Req, State);
        false ->
            {response(405), Req, State}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Authentication
%% ------------------------------------------------------------------

-spec check_authentication(req(), state()) -> {response(), req(), state()}.
check_authentication(Req, State) ->
    ParseResult = cowboy_req:parse_header(<<"authorization">>, Req),
    case handle_parsed_authentication(ParseResult, State) of
        {valid, State2} ->
            check_form(Req, State2);
        {invalid, State2} ->
            {response(401, failed_auth_prompt_headers()), Req, State2};
        {bad_header, State2} ->
            set_result(400, {bad_header, authorization}, Req, State2)
    end.

-spec handle_parsed_authentication(ParseResult, state())
        -> {valid | bad_header | invalid, state()}
             when ParseResult :: Valid | Invalid,
                  Valid :: {basic, username(), password()},
                  Invalid :: tuple() | undefined.
handle_parsed_authentication({basic, Username, Password}, State) ->
    #{ backwater_opts := BackwaterOpts } = State,
    AuthenticatedAccessConfs = maps:get(authenticated_access, BackwaterOpts, #{}),
    validate_authentication(maps:find(Username, AuthenticatedAccessConfs), Password, State);
handle_parsed_authentication(undefined, State) ->
    #{ backwater_opts := BackwaterOpts } = State,
    ExplicitAccessConf = maps:get(unauthenticated_access, BackwaterOpts, #{}),
    DefaultAccessConf = default_access_conf(unauthenticated_access),
    AccessConf = maps:merge(DefaultAccessConf, ExplicitAccessConf),
    State2 = State#{ access_conf => AccessConf },
    {valid, State2};
handle_parsed_authentication(_Other, State) ->
    {bad_header, State}.

-spec validate_authentication({ok, access_conf()} | error, password(), state())
        -> {valid | invalid, state()}.
validate_authentication({ok, #{ authentication := {basic, Password} } = ExplicitAccessConf},
                        GivenPassword, State)
  when Password =:= GivenPassword ->
    DefaultAccessConf = default_access_conf(authenticated_access),
    AccessConf = maps:merge(DefaultAccessConf, ExplicitAccessConf),
    State2 = State#{ access_conf => AccessConf },
    {valid, State2};
validate_authentication({ok, #{ authentication := {basic, _Password} }},
                        _GivenPassword, State) ->
    {invalid, State};
validate_authentication(error, _GivenPassword, State) ->
    {invalid, State}.

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
%% Internal Function Definitions - Check Request Form
%% ------------------------------------------------------------------

-spec check_form(req(), state()) -> {response(), req(), state()}.
check_form(Req, State) ->
    case validate_form(Req, State) of
        {valid, Req2, State2} ->
            check_authorization(Req2, State2);
        {InvalidReason, Req2, State2} ->
            set_result(400, InvalidReason, Req2, State2)
    end.

-spec validate_form(req(), state())
        -> {valid | Error, req(), state()}
             when Error :: (invalid_api_version | invalid_module_name |
                            invalid_function_name | invalid_function_arity).
validate_form(Req, State) ->
    #{ unvalidated_version := UnvalidatedVersion,
       unvalidated_module := UnvalidatedModule,
       unvalidated_function := UnvalidatedFunction,
       unvalidated_arity := UnvalidatedArity } = State,

    Version = backwater_util:fast_catch(fun unicode:characters_to_binary/1, [UnvalidatedVersion]),
    BinModule = backwater_util:fast_catch(fun unicode:characters_to_binary/1, [UnvalidatedModule]),
    BinFunction = backwater_util:fast_catch(fun unicode:characters_to_binary/1, [UnvalidatedFunction]),
    Arity = backwater_util:fast_catch(fun binary_to_integer/1, [UnvalidatedArity]),

    if not is_binary(Version) ->
           {invalid_api_version, Req, State};
       not is_binary(BinModule) orelse byte_size(BinModule) < 1 orelse byte_size(BinModule) > 255 ->
           {invalid_module_name, Req, State};
       not is_binary(BinFunction) orelse byte_size(BinFunction) < 1 orelse byte_size(BinFunction) > 255 ->
           {invalid_function_name, Req, State};
       not is_integer(Arity) orelse Arity < 0 orelse Arity > 255 ->
           {invalid_function_arity, Req, State};
       true ->
           NewState =
                State#{ version => Version,
                        bin_module => BinModule,
                        bin_function => BinFunction,
                        arity => Arity },
           {valid, Req, NewState}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Request Authorization
%% ------------------------------------------------------------------

-spec check_authorization(req(), state()) -> {response(), req(), state()}.
check_authorization(Req, State) ->
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
        true ->
            check_existence(Req, State);
        false ->
            %Req2 = set_resp_body({error, module_not_exposed}, Req),
            {response(403), Req, State}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Resource Existence
%% ------------------------------------------------------------------

-spec check_existence(req(), state()) -> {response(), req(), state()}.
check_existence(Req, State) ->
    case find_resource(Req, State) of
        {found, Req2, State2} ->
            check_args_content_type(Req2, State2);
        {NotFound, Req2, State2} ->
            set_result(404, NotFound, Req2, State2)
    end.

-spec find_resource(req(), state())
        -> {found | Error, req(), state()}
             when Error :: (module_version_not_found |
                            function_not_exported |
                            module_not_found).
find_resource(Req, State) ->
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
            {module_version_not_found, Req, State};
        {ok, #{ exports := Exports } = ModuleInfo} ->
            case maps:find({BinFunction, Arity}, Exports) of
                {ok, Resource} ->
                    State2 = State#{ module_info => ModuleInfo, function_properties => Resource },
                    {found, Req, State2};
                error ->
                    {function_not_exported, Req, State}
            end;
        error ->
            {module_not_found, Req, State}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Arguments Content Type
%% ------------------------------------------------------------------

-spec check_args_content_type(req(), state()) -> {response(), req(), state()}.
check_args_content_type(Req, State) ->
    case cowboy_req:parse_header(<<"content-type">>, Req) of
        {_, _, _} = ContentType ->
            State2 = State#{ args_content_type => ContentType },
            check_args_content_encoding(Req, State2);
        undefined ->
            set_result(400, {bad_header, 'content-type'}, Req, State)
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Arguments Content Encoding
%% ------------------------------------------------------------------

-spec check_args_content_encoding(req(), state()) -> {response(), req(), state()}.
check_args_content_encoding(Req, State) ->
    case cowboy_req:header(<<"content-encoding">>, Req) of
        <<ContentEncoding/binary>> ->
            State2 = State#{ args_content_encoding => ContentEncoding },
            check_accepted_result_content_types(Req, State2);
        undefined ->
            State2 = State#{ args_content_encoding => <<"identity">> },
            check_accepted_result_content_types(Req, State2)
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Accepted Content Types
%% ------------------------------------------------------------------

-spec check_accepted_result_content_types(req(), state()) -> {response(), req(), state()}.
check_accepted_result_content_types(Req, State) ->
    AcceptedContentTypes = cowboy_req:parse_header(<<"accept">>, Req, []),
    SortedAcceptedContentTypes = lists:reverse( lists:keysort(2, AcceptedContentTypes) ),
    State2 = State#{ accepted_result_content_types => SortedAcceptedContentTypes },
    negotiate_args_content_type(Req, State2).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Negotiate Arguments Content Type
%% ------------------------------------------------------------------

-spec negotiate_args_content_type(req(), state()) -> {response(), req(), state()}.
negotiate_args_content_type(Req, State) ->
    #{ function_properties := FunctionProperties,
       args_content_type := ArgsContentType } = State,
    #{ known_content_types := KnownContentTypes } = FunctionProperties,

    {Type, SubType, _ContentTypeParams} = ArgsContentType,
    SearchResult = lists:member({Type, SubType}, KnownContentTypes),

    case SearchResult of
        true -> negotiate_args_content_encoding(Req, State);
        false -> set_result(415, unsupported_content_type, Req, State)
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Negotiate Arguments Content Encoding
%% ------------------------------------------------------------------

-spec negotiate_args_content_encoding(req(), state()) -> {response(), req(), state()}.
negotiate_args_content_encoding(Req, State) ->
    #{ args_content_encoding := ArgsContentEncoding } = State,
    case lists:member(ArgsContentEncoding, [<<"identity">>, <<"gzip">>]) of
        true -> negotiate_result_content_type(Req, State);
        false -> set_result(415, unsupported_content_encoding, Req, State)
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Negotiate Result Content Type
%% ------------------------------------------------------------------

-spec negotiate_result_content_type(req(), state()) -> {response(), req(), state()}.
negotiate_result_content_type(Req, State) ->
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
            read_and_decode_args(Req, State2);
        false ->
            {response(406), Req, State}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Read and Decode Arguments
%% ------------------------------------------------------------------

-spec read_and_decode_args(req(), state()) -> {response(), req(), state()}.
read_and_decode_args(Req, State) ->
    case cowboy_req:read_body(Req) of
        {ok, Data, Req2} ->
            decode_args_content_encoding(Data, Req2, State);
        {more, _Data, Req2} ->
            {response(413), Req2, State}
    end.

-spec decode_args_content_encoding(binary(), req(), state()) -> {response(), req(), state()}.
decode_args_content_encoding(Data, Req, #{ args_content_encoding := <<"identity">> } = State) ->
    decode_args_content_type(Data, Req, State);
decode_args_content_encoding(Data, Req, #{ args_content_encoding := <<"gzip">> } = State) ->
    case backwater_encoding_gzip:decode(Data) of
        {ok, UncompressedData} ->
            decode_args_content_type(UncompressedData, Req, State);
        {error, _} ->
            set_result(400, unable_to_uncompress_body, Req, State)
    end.

-spec decode_args_content_type(binary(), req(), state()) -> {response(), req(), state()}.
decode_args_content_type(Data, Req, State) ->
    #{ args_content_type := ArgsContentType } = State,
    case ArgsContentType of
        {<<"application">>, <<"x-erlang-etf">>, _Params} ->
            decode_etf_args(Data, Req, State)
    end.

-spec decode_etf_args(binary(), req(), state()) -> {response(), req(), state()}.
decode_etf_args(Data, Req, State) ->
    #{ access_conf := AccessConf } = State,
    #{ decode_unsafe_terms := DecodeUnsafeTerms } = AccessConf,
    case backwater_media_etf:decode(Data, DecodeUnsafeTerms) of
        error ->
            %Req3 = set_resp_body({error, undecodable_payload}, Req2),
            set_result(400, unable_to_decode_arguments, Req, State);
        {ok, UnvalidatedArgs} ->
            validate_args(UnvalidatedArgs, Req, State)
    end.

-spec validate_args(term(), req(), state()) -> {response(), req(), state()}.
validate_args(UnvalidatedArgs, Req, State)
  when not is_list(UnvalidatedArgs) ->
    set_result(400, arguments_not_a_list, Req, State);
validate_args(UnvalidatedArgs, Req, #{ arity := Arity } = State)
  when length(UnvalidatedArgs) =/= Arity ->
    set_result(400, inconsistent_arguments_arity, Req, State);
validate_args(Args, Req, State) ->
    handle_call(Args, Req, State).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Execute Call
%% ------------------------------------------------------------------

-spec handle_call([term()], req(), state()) -> {response(), req(), state()}.
handle_call(Args, Req, State) ->
    #{ access_conf := AccessConf, function_properties := FunctionProperties } = State,
    #{ function_ref := FunctionRef } = FunctionProperties,
    Result = call_function(FunctionRef, Args, AccessConf),
    set_result(200, Result, Req, State).

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
%% Internal Function Definitions - Encode Result
%% ------------------------------------------------------------------

-spec set_result(http_status(), term(), req(), state()) -> {response(), req(), state()}.
set_result(StatusCode, Result, Req, #{ result_content_type := ResultContentType } = State) ->
    {Type, SubType, _Params} = ResultContentType,
    ContentTypeHeaders = #{ <<"content-type">> => [Type, "/", SubType] },
    Data = encode_result_body(Result, ResultContentType),
    {response(StatusCode, ContentTypeHeaders, Data), Req, State};
set_result(StatusCode, Result, Req, State) ->
    Data = io_lib:format("~p", [Result]),
    {response(StatusCode, #{}, Data), Req, State}.

-spec encode_result_body(term(), content_type()) -> binary().
encode_result_body(Result, {<<"application">>, <<"x-erlang-etf">>, _Params}) ->
    backwater_media_etf:encode(Result).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Utilities
%% ------------------------------------------------------------------

-spec response(http_status()) -> response().
response(StatusCode) ->
    #{ status_code => StatusCode }.

-spec response(http_status(), http_headers()) -> response().
response(StatusCode, Headers) ->
    (response(StatusCode))#{ headers => Headers }.

-spec response(http_status(), http_headers(), iodata()) -> response().
response(StatusCode, Headers, Body) ->
    (response(StatusCode, Headers))#{ body => Body }.

-spec nocache_headers() -> http_headers().
nocache_headers() ->
    #{ <<"cache-control">> => <<"private, no-cache, no-store, must-revalidate">>,
       <<"pragma">> => <<"no-cache">>,
       <<"expires">> => <<"0">> }.
