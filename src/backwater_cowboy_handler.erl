-module(backwater_cowboy_handler).

%% ------------------------------------------------------------------
%% cowboy_http_handler Function Exports
%% ------------------------------------------------------------------

-export([init/3]).
-export([rest_init/2]).
-export([rest_terminate/2]).

-export([allowed_methods/2]).
-export([allow_missing_post/2]).
-export([content_types_accepted/2]).
-export([content_types_provided/2]).
-export([expires/2]).
-export([forbidden/2]).
-export([is_authorized/2]).
-export([known_methods/2]).
-export([malformed_request/2]).
-export([resource_exists/2]).

-export([handle_etf_body/2]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

%% ------------------------------------------------------------------
%% cowboy_http_handler Function Definitions
%% ------------------------------------------------------------------

init(_Transport, _Req, _Opts) ->
    {upgrade, protocol, cowboy_rest}.

rest_init(Req, [BackwaterOpts]) ->
    {BinVersion, Req2} = cowboy_req:binding(version, Req),
    {BinModule, Req3} = cowboy_req:binding(module, Req2),
    {BinFunction, Req4} = cowboy_req:binding(function, Req3),
    {BinArity, Req5} = cowboy_req:binding(arity, Req4),
    {ok, Req5, #{ backwater_opts => BackwaterOpts,
                  unvalidated_version => BinVersion,
                  unvalidated_module => BinModule,
                  unvalidated_function => BinFunction,
                  unvalidated_arity => BinArity
                }}.

rest_terminate(_Req, _State) ->
    ok.

allowed_methods(Req, State) ->
    {[<<"POST">>], Req, State}.

allow_missing_post(Req, State) ->
    {false, Req, State}.

content_types_accepted(Req, State) ->
    {[
      {{<<"application">>, <<"x-erlang-etf">>, []},
       handle_etf_body}
     ],
     Req, State}.

content_types_provided(Req, State) ->
    {[
      {{<<"application">>, <<"x-erlang-etf">>, []},
       non_existent_function} % we only handle POSTs; this will never be called
     ],
     Req, State}.

expires(Req, State) ->
    {[{1970,1,1}, {0,0,0}], Req, State}.

forbidden(Req, State) ->
    #{ module := Module,
       access_conf := AccessConf } = State,
    #{ exposed_modules := ExposedModules } = AccessConf,

    case not lists:member(Module, ExposedModules) of
        false ->
            {false, Req, State};
        true ->
            Req2 = set_resp_body({error, module_not_exposed}, Req),
            {true, Req2, State}
    end.

is_authorized(Req, #{ is_authorized_value := IsAuthenticatedValue } = State) ->
    % XXX: Long story short, we need to authorize the user before verifying
    % whether the request is well formed (due to 'decode_unsafe_terms');
    % therefore we do it on malformed_request/2 and cache the result,
    % which we can now return.
    {IsAuthenticatedValue, Req, State}.

known_methods(Req, State) ->
    {[<<"POST">>], Req, State}.

malformed_request(Req, State) ->
    case is_authorized_(Req, State) of
        {false, Req2, NewState} ->
            {false, Req2, NewState#{ is_authorized_value => {false, failed_authorization_prompt()} }};
        {true, Req2, NewState} ->
            malformed_request_(Req2, NewState#{ is_authorized_value => true })
    end.

resource_exists(Req, State) ->
    #{ version := Version,
       module := Module,
       function := Function,
       arity := Arity } = State,

    case find_and_parse_relevant_module_info(Module) of
        {ok, #{ backwater_version := BackwaterVersion }} when BackwaterVersion =/= Version ->
            Req2 = set_resp_body({error, module_version_not_found}, Req),
            {false, Req2, State};
        {ok, #{ backwater_exports := BackwaterExports, exports := Exports }} ->
            case (maps:is_key({Function, Arity}, BackwaterExports) andalso
                  lists:member({Function, Arity}, Exports)) of
                true ->
                    {true, Req, State};
                false ->
                    Req2 = set_resp_body({error, function_not_exported}, Req),
                    {false, Req2, State}
            end;
        error ->
            Req2 = set_resp_body({error, module_not_found}, Req),
            {false, Req2, State}
    end.

handle_etf_body(Req, State) ->
    #{ arity := Arity,
       access_conf := AccessConf } = State,
    #{ decode_unsafe_terms := DecodeUnsafeTerms } = AccessConf,

    {ok, Body, Req2} = cowboy_req:body(Req),
    case backwater_codec_etf:decode(Body, DecodeUnsafeTerms) of
        error ->
            Req3 = set_resp_body({error, undecodable_payload}, Req2),
            {false, Req3, State};
        {ok, UnvalidatedFunctionArgs} ->
            if not is_list(UnvalidatedFunctionArgs) ->
                   Req3 = set_resp_body({error, payload_not_a_list}, Req2),
                   {false, Req3, State};
               length(UnvalidatedFunctionArgs) =/= Arity ->
                   Req3 = set_resp_body({error, payload_arity_inconsistent}, Req2),
                   {false, Req3, State};
               true ->
                   NewState = State#{ function_args => UnvalidatedFunctionArgs },
                   handle_call(Req2, NewState)
            end
    end.

%% ------------------------------------------------------------------
%% Internal Function Exports
%% ------------------------------------------------------------------

utf8bin_to_atom(BinValue, #{ decode_unsafe_terms := true }) ->
    binary_to_atom(BinValue, utf8);
utf8bin_to_atom(BinValue, #{ decode_unsafe_terms := false }) ->
    binary_to_existing_atom(BinValue, utf8).

find_and_parse_relevant_module_info(Module) ->
    case find_module_info(Module) of
        {ok, ModuleInfo} ->
            {attributes, ModuleAttributes} = lists:keyfind(attributes, 1, ModuleInfo),
            {exports, Exports} = lists:keyfind(exports, 1, ModuleInfo),
            case module_attributes_find_backwater_version(ModuleAttributes) of
                {ok, BackwaterVersion} ->
                    BackwaterExports = module_attributes_get_backwater_exports(ModuleAttributes),
                    {ok, #{ exports => Exports,
                            backwater_version => BackwaterVersion,
                            backwater_exports => BackwaterExports }};
                error ->
                    error
            end;
        error ->
            error
    end.

find_module_info(Module) ->
    try
        {ok, Module:module_info()}
    catch
        error:undef -> error
    end.

module_attributes_find_backwater_version(ModuleAttributes) ->
    case lists:keyfind(backwater_version, 1, ModuleAttributes) of
        {backwater_version, Version} ->
            {ok, Version};
        false ->
            error
    end.

module_attributes_get_backwater_exports(ModuleAttributes) ->
    lists:foldl(
      fun ({backwater_export, Tuple}, Acc) when is_tuple(Tuple) ->
              {FA, Properties} = backwater_export_entry_pair(Tuple),
              maps:put(FA, Properties, Acc);
          ({backwater_export, List}, Acc) when is_list(List) ->
              EntryPairs = lists:map(fun backwater_export_entry_pair/1, List),
              maps:merge(Acc, maps:from_list(EntryPairs));
          (_Other, Acc) ->
              Acc
      end,
      #{},
      ModuleAttributes).

backwater_export_entry_pair({F,A}) ->
    Properties = #{}, % none yet
    {{F,A}, Properties}.

call_function(Module, Function, Args, #{ return_exception_stacktraces := ReturnExceptionStacktraces }) ->
    try
        {success, apply(Module, Function, Args)}
    catch
        Class:Exception when ReturnExceptionStacktraces ->
            Stacktrace = erlang:get_stacktrace(),
            CleanStacktrace = clean_exception_stacktrace(Stacktrace, {?MODULE,call_function,4}),
            {exception, Class, Exception, CleanStacktrace};
        Class:Exception ->
            {exception, Class, Exception, []}
    end.

clean_exception_stacktrace(Stacktrace, UntilMFA) ->
    lists:takewhile(
      fun ({M,F,A,_Extra}) -> {M,F,A} =/= UntilMFA end,
      Stacktrace).

is_authorized_(Req, State) ->
    ParseResult = cowboy_req:parse_header(<<"authorization">>, Req, none),
    handle_req_auth_parse(ParseResult, Req, State).

handle_req_auth_parse({ok, {<<"basic">>, {Username, Password}}, Req}, _PrevReq, State) ->
    #{ backwater_opts := BackwaterOpts } = State,
    AuthenticatedAccessConfs = maps:get(authenticated_access, BackwaterOpts, #{}),
    authenticate_req_auth(maps:find(Username, AuthenticatedAccessConfs), Password, Req, State);
handle_req_auth_parse({ok, none, Req}, _PrevReq, State) ->
    #{ backwater_opts := BackwaterOpts } = State,
    ExplicitAccessConf = maps:get(unauthenticated_access, BackwaterOpts, #{}),
    DefaultAccessConf = default_access_conf(unauthenticated_access),
    AccessConf = maps:merge(DefaultAccessConf, ExplicitAccessConf),
    NewState = State#{ access_conf => AccessConf },
    {true, Req, NewState};
handle_req_auth_parse({undefined, _Value, Req}, _PrevReq, State) ->
    {false, Req, State};
handle_req_auth_parse({error, badarg}, PrevReq, State) ->
    {false, PrevReq, State}.

authenticate_req_auth({ok, #{ authentication := {basic, Password} } = ExplicitAccessConf},
                      GivenPassword, Req, State) 
  when Password =:= GivenPassword ->
    DefaultAccessConf = default_access_conf(authenticated_access),
    AccessConf = maps:merge(DefaultAccessConf, ExplicitAccessConf),
    NewState = State#{ access_conf => AccessConf },
    {true, Req, NewState};
authenticate_req_auth({ok, #{ authentication := {basic, _Password} }},
                      _GivenPassword, Req, State) ->
    {false, Req, State};
authenticate_req_auth(error, _GivenPassword, Req, State) ->
    {false, Req, State}.

default_access_conf(unauthenticated_access) ->
    #{ decode_unsafe_terms => false,
       exposed_modules => [],
       return_exception_stacktraces => false };
default_access_conf(authenticated_access) ->
    #{ decode_unsafe_terms => true,
       exposed_modules => [],
       return_exception_stacktraces => true }.

failed_authorization_prompt() ->
    <<"Basic realm=\"backwater\"">>.

malformed_request_(Req, State) ->
    #{ access_conf := AccessConf,
       unvalidated_version := BinVersion,
       unvalidated_module := BinModule,
       unvalidated_function := BinFunction,
       unvalidated_arity := BinArity } = State,

    Version = (catch unicode:characters_to_list(BinVersion)),
    Module = (catch utf8bin_to_atom(BinModule, AccessConf)),
    Function = (catch utf8bin_to_atom(BinFunction, AccessConf)),
    Arity = (catch binary_to_integer(BinArity)),

    if not is_list(Version) ->
           Req2 = set_resp_body({error, invalid_api_version}, Req),
           {true, Req2, State};
       not is_atom(Module) ->
           Req2 = set_resp_body({error, invalid_module_name}, Req),
           {true, Req2, State};
       not is_atom(Function) ->
           Req2 = set_resp_body({error, invalid_function_name}, Req),
           {true, Req2, State};
       not is_integer(Arity) orelse Arity < 0 orelse Arity > 255 ->
           Req2 = set_resp_body({error, invalid_function_arity}, Req),
           {true, Req2, State};
       true ->
           NewState =
                State#{ version => Version,
                        module => Module,
                        function => Function,
                        arity => Arity },
           {false, Req, NewState}
    end.

handle_call(Req, State) ->
    #{ access_conf := AccessConf,
       module := Module,
       function := Function,
       function_args := Args } = State,

    Result = call_function(Module, Function, Args, AccessConf),
    Req2 = set_resp_body(Result, Req),
    {true, Req2, State}.

set_resp_body(Term, Req) ->
    {Body, Req2} = encode_resp_body(Term, Req),
    cowboy_req:set_resp_body(Body, Req2).

encode_resp_body(Term, Req) ->
    {ResponseMediaType, Req2} = cowboy_req:meta(media_type, Req),
    case ResponseMediaType of
        {<<"application">>, <<"x-erlang-etf">>, _} ->
            {backwater_codec_etf:encode(Term), Req2};
        undefined ->
            {io_lib:format("~p", [Term]), Req2}
    end.
