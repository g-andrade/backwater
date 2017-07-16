-module(backwater_cowboy_handler).

-include("backwater_common.hrl").

%% ------------------------------------------------------------------
%% cowboy_http_handler Function Exports
%% ------------------------------------------------------------------

-export([init/3]).
-export([handle/2]).
-export([terminate/3]).

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
           module => module(),
           function => atom(),
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
        #{ protocol => backwater_cowboy_protocol(),
           number_of_acceptors => pos_integer(),
           transport_options => backwater_transport_opts(),
           protocol_options => backwater_protocol_options() }.

-type backwater_cowboy_protocol() :: http | https.

-type backwater_transport_opts() :: ranch_tcp:opts() | ranch_ssl:opts().

-type backwater_protocol_options() :: cowboy_protocol:opts().


-type access_conf() ::
        #{ decode_unsafe_terms := boolean(),
           exposed_modules := [module()],
           return_exception_stacktraces := boolean(),
           authentication => {basic, password()} }.

-type username() :: nonempty_binary().
-type password() :: nonempty_binary().

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

-type parse_header_result(T) ::
        ({ok, T, req()} |
         {undefined, binary(), req()} |
         {error, badarg}).

-type call_result() ::
        ({success, term()} |
         {exception, Class :: term(), Exception :: term(), [erlang:stack_item()]}).

%% ------------------------------------------------------------------
%% cowboy_http_handler Function Definitions
%% ------------------------------------------------------------------

-spec init(module(), req(), [backwater_opts(), ...]) -> {ok, req(), state()}.
init(_Transport, Req, [BackwaterOpts]) ->
    {BinVersion, Req2} = cowboy_req:binding(version, Req),
    {BinModule, Req3} = cowboy_req:binding(module, Req2),
    {BinFunction, Req4} = cowboy_req:binding(function, Req3),
    {BinArity, Req5} = cowboy_req:binding(arity, Req4),
    State = #{ backwater_opts => BackwaterOpts,
               unvalidated_version => BinVersion,
               unvalidated_module => BinModule,
               unvalidated_function => BinFunction,
               unvalidated_arity => BinArity
             },
    {ok, Req5, State}.

-spec handle(req(), state()) -> {ok, req(), state()}.
handle(Req, State) ->
    {Response, Req2, State2} = handle_method(Req, State),
    StatusCode = maps:get(status_code, Response),
    ResponseHeaders = maps:get(headers, Response, []),
    ResponseBody = maps:get(body, Response, <<>>),
    ResponseHeadersWithNoCache = nocache_headers() ++ ResponseHeaders,
    {ok, Req3} = cowboy_req:reply(StatusCode, ResponseHeadersWithNoCache, ResponseBody, Req2),
    {ok, Req3, State2}.

-spec terminate(term(), req(), state()) -> ok.
terminate(_Reason, _Req, _State) ->
    ok.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Method
%% ------------------------------------------------------------------

-spec handle_method(req(), state()) -> {response(), req(), state()}.
handle_method(Req, State) ->
    case cowboy_req:method(Req) of
        {<<"POST">>, Req2} ->
            check_authentication(Req2, State);
        {_, Req2} ->
            {response(405), Req2, State}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Authentication
%% ------------------------------------------------------------------

-spec check_authentication(req(), state()) -> {response(), req(), state()}.
check_authentication(Req, State) ->
    ParseResult = cowboy_req:parse_header(<<"authorization">>, Req),
    case handle_parsed_authentication(ParseResult, Req, State) of
        {valid, Req2, State2} ->
            check_form(Req2, State2);
        {invalid, Req2, State2} ->
            {response(401, [failed_auth_prompt_header()]), Req2, State2};
        {bad_header, Req2, State2} ->
            set_result(400, {bad_header, authorization}, Req2, State2)
    end.

-spec handle_parsed_authentication(ParseResult, req(), state())
        -> {valid | bad_header | invalid, req(), state()}
             when ParseResult :: parse_header_result(Valid | Invalid),
                  Valid :: {binary(), {username(), password()}},
                  Invalid :: {binary(), term()}.
handle_parsed_authentication({ok, {<<"basic">>, {Username, Password}}, Req}, _PrevReq, State) ->
    #{ backwater_opts := BackwaterOpts } = State,
    AuthenticatedAccessConfs = maps:get(authenticated_access, BackwaterOpts, #{}),
    validate_authentication(maps:find(Username, AuthenticatedAccessConfs), Password, Req, State);
handle_parsed_authentication({ok, _, Req}, _PrevReq, State) ->
    #{ backwater_opts := BackwaterOpts } = State,
    ExplicitAccessConf = maps:get(unauthenticated_access, BackwaterOpts, #{}),
    DefaultAccessConf = default_access_conf(unauthenticated_access),
    AccessConf = maps:merge(DefaultAccessConf, ExplicitAccessConf),
    State2 = State#{ access_conf => AccessConf },
    {valid, Req, State2};
handle_parsed_authentication({undefined, _Unparsable, Req}, _PrevReq, State) ->
    {bad_header, Req, State};
handle_parsed_authentication({error, badarg}, PrevReq, State) ->
    {bad_header, PrevReq, State}.

-spec validate_authentication({ok, access_conf()} | error, password(), req(), state())
        -> {valid | invalid, req(), state()}.
validate_authentication({ok, #{ authentication := {basic, Password} } = ExplicitAccessConf},
                        GivenPassword, Req, State)
  when Password =:= GivenPassword ->
    DefaultAccessConf = default_access_conf(authenticated_access),
    AccessConf = maps:merge(DefaultAccessConf, ExplicitAccessConf),
    State2 = State#{ access_conf => AccessConf },
    {valid, Req, State2};
validate_authentication({ok, #{ authentication := {basic, _Password} }},
                      _GivenPassword, Req, State) ->
    {invalid, Req, State};
validate_authentication(error, _GivenPassword, Req, State) ->
    {invalid, Req, State}.

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
failed_auth_prompt_header() ->
    {<<"www-authenticate">>, <<"Basic realm=\"backwater\"">>}.

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
    #{ access_conf := AccessConf,
       unvalidated_version := BinVersion,
       unvalidated_module := BinModule,
       unvalidated_function := BinFunction,
       unvalidated_arity := BinArity } = State,

    Version = (catch unicode:characters_to_binary(BinVersion)),
    Module = (catch utf8bin_to_atom(BinModule, AccessConf)),
    Function = (catch utf8bin_to_atom(BinFunction, AccessConf)),
    Arity = (catch binary_to_integer(BinArity)),

    if not is_binary(Version) ->
           {invalid_api_version, Req, State};
       not is_atom(Module) ->
           {invalid_module_name, Req, State};
       not is_atom(Function) ->
           {invalid_function_name, Req, State};
       not is_integer(Arity) orelse Arity < 0 orelse Arity > 255 ->
           {invalid_function_arity, Req, State};
       true ->
           NewState =
                State#{ version => Version,
                        module => Module,
                        function => Function,
                        arity => Arity },
           {valid, Req, NewState}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Check Request Authorization
%% ------------------------------------------------------------------

-spec check_authorization(req(), state()) -> {response(), req(), state()}.
check_authorization(Req, State) ->
    #{ module := Module,
       access_conf := AccessConf } = State,
    #{ exposed_modules := ExposedModules } = AccessConf,

    case lists:member(Module, ExposedModules) of
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
    #{ version := RequiredVersion,
       module := RequiredModule,
       function := RequiredFunction,
       arity := RequiredArity } = State,

    case backwater_module_info:find(RequiredModule) of
        {ok, #{ version := Version }} when Version =/= RequiredVersion ->
            {module_version_not_found, Req, State};
        {ok, #{ exports := Exports } = ModuleInfo} ->
            case maps:find({RequiredFunction, RequiredArity}, Exports) of
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
    ParseResult = cowboy_req:parse_header(<<"content-type">>, Req),
    case handle_parsed_content_type(ParseResult, Req) of
        {{valid, ContentType}, Req2} ->
            State2 = State#{ args_content_type => ContentType },
            check_args_content_encoding(Req2, State2);
        {bad_header, Req2} ->
            set_result(400, {bad_header, 'content-type'}, Req2, State)
    end.

-spec handle_parsed_content_type(parse_header_result(content_type()), req())
        -> {{valid, content_type()} | bad_header, req()}.
handle_parsed_content_type({ok, {_, _, _} = ContentType, Req}, _PrevReq) ->
    {{valid, ContentType}, Req};
handle_parsed_content_type({ok, _, Req}, _PrevReq) ->
    {bad_header, Req};
handle_parsed_content_type({undefined, _Unparsable, Req}, _PrevReq) ->
    {bad_header, Req};
handle_parsed_content_type({error, badarg}, Req) ->
    {bad_header, Req}.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Arguments Content Encoding
%% ------------------------------------------------------------------

-spec check_args_content_encoding(req(), state()) -> {response(), req(), state()}.
check_args_content_encoding(Req, State) ->
    case cowboy_req:header(<<"content-encoding">>, Req) of
        {<<ContentEncoding/binary>>, Req2} ->
            State2 = State#{ args_content_encoding => ContentEncoding },
            check_accepted_result_content_types(Req2, State2);
        {undefined, Req2} ->
            State2 = State#{ args_content_encoding => <<"identity">> },
            check_accepted_result_content_types(Req2, State2)
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Validate Accepted Content Types
%% ------------------------------------------------------------------

-spec check_accepted_result_content_types(req(), state()) -> {response(), req(), state()}.
check_accepted_result_content_types(Req, State) ->
    ParseResult = cowboy_req:parse_header(<<"accept">>, Req, []),
    case handle_parsed_accept(ParseResult, Req) of
        {{valid, AcceptedContentTypes}, Req2} ->
            State2 = State#{ accepted_result_content_types => AcceptedContentTypes },
            negotiate_args_content_type(Req2, State2);
        {bad_header, Req2} ->
            set_result(400, {bad_header, accept}, Req2, State)
    end.

-spec handle_parsed_accept(parse_header_result([accepted_content_type()]), req())
        -> {{valid, [accepted_content_type()]} | bad_header, req()}.
handle_parsed_accept({ok, AcceptedContentTypes, Req}, _PrevReq) when is_list(AcceptedContentTypes) > 0 ->
    SortedAcceptedContentTypes = lists:reverse( lists:keysort(2, AcceptedContentTypes) ),
    {{valid, SortedAcceptedContentTypes}, Req};
handle_parsed_accept({undefined, _Unparsable, Req}, _PrevReq) ->
    {bad_header, Req};
handle_parsed_accept({error, badarg}, Req) ->
    {bad_header, Req}.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Negotiate Arguments Content Type
%% ------------------------------------------------------------------

-spec negotiate_args_content_type(req(), state()) -> {response(), req(), state()}.
negotiate_args_content_type(Req, State) ->
    #{ function_properties := FunctionProperties,
       args_content_type := ArgsContentType } = State,
    #{ known_content_types := KnownContentTypes } = FunctionProperties,

    {Type, SubType, _ContentTypeParams} = ArgsContentType,
    SearchResult =
        lists:any(
          fun ({KnownType, KnownSubType}) ->
                  (KnownType =:= Type andalso KnownSubType =:= SubType)
          end,
          KnownContentTypes),

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
    case cowboy_req:body(Req) of
        {ok, Data, Req2} ->
            decode_args_content_encoding(Data, Req2, State);
        {more, _Data, Req2} ->
            {response(413), Req2, State};
        {error, _Error} ->
            set_result(400, unable_to_read_body, Req, State)
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
    #{ access_conf := AccessConf, module := Module, function := Function } = State,
    Result = call_function(Module, Function, Args, AccessConf),
    set_result(200, Result, Req, State).

-spec call_function(module(), atom(), [term()], access_conf()) -> call_result().
call_function(Module, Function, Args, #{ return_exception_stacktraces := ReturnExceptionStacktraces }) ->
    try
        {success, apply(Module, Function, Args)}
    catch
        Class:Exception when ReturnExceptionStacktraces ->
            Stacktrace = erlang:get_stacktrace(),
            % Hide all calls previous to the one made to the target function (cowboy stuff, etc.)
            % This works under the assumption that *no sensible call* would ever go through the
            % current function again.
            PurgedStacktrace = backwater_util:purge_stacktrace_below({?MODULE,call_function,4}, Stacktrace),
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
    ContentTypeHeader = {<<"content-type">>, <<Type/binary, "/", SubType/binary>>},
    Data = encode_result_body(Result, ResultContentType),
    {response(StatusCode, [ContentTypeHeader], Data), Req, State};
set_result(StatusCode, Result, Req, State) ->
    Data = io_lib:format("~p", [Result]),
    {response(StatusCode, [], Data), Req, State}.

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

-spec utf8bin_to_atom(binary(), access_conf()) -> atom() | no_return().
utf8bin_to_atom(BinValue, #{ decode_unsafe_terms := true }) ->
    binary_to_atom(BinValue, utf8);
utf8bin_to_atom(BinValue, #{ decode_unsafe_terms := false }) ->
    binary_to_existing_atom(BinValue, utf8).

-spec nocache_headers() -> http_headers().
nocache_headers() ->
    [{<<"cache-control">>, <<"private, no-cache, no-store, must-revalidate">>},
     {<<"pragma">>, <<"no-cache">>},
     {<<"expires">>, <<"0">>}].
