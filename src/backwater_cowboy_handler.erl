-module(backwater_cowboy_handler).

%% ------------------------------------------------------------------
%% cowboy_http_handler Function Exports
%% ------------------------------------------------------------------

-export([init/3]).
-export([handle/2]).
-export([terminate/3]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

%% ------------------------------------------------------------------
%% cowboy_http_handler Function Definitions
%% ------------------------------------------------------------------

init(_Transport, Req, [Ref, BackwaterOpts]) ->
    {BinVersion, Req2} = cowboy_req:binding(version, Req),
    {BinModule, Req3} = cowboy_req:binding(module, Req2),
    {BinFunction, Req4} = cowboy_req:binding(function, Req3),
    {BinArity, Req5} = cowboy_req:binding(arity, Req4),
    {ok, Req5, #{ ref => Ref,
                  backwater_opts => BackwaterOpts,
                  unvalidated_version => BinVersion,
                  unvalidated_module => BinModule,
                  unvalidated_function => BinFunction,
                  unvalidated_arity => BinArity
                }}.

handle(Req, State) ->
    {Response, Req2, State2} = handle_method(Req, State),
    StatusCode = maps:get(status_code, Response),
    ResponseHeaders = maps:get(headers, Response, []),
    ResponseBody = maps:get(body, Response, []),
    {ok, Req3} = cowboy_req:reply(StatusCode, ResponseHeaders, ResponseBody, Req2),
    {ok, Req3, State2}.

terminate(_Reason, _Req, _State) ->
    ok.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% utilities

response(StatusCode) ->
    #{ status_code => StatusCode }.

response(StatusCode, Headers) ->
    (response(StatusCode))#{ headers => Headers }.

response(StatusCode, Headers, Body) ->
    (response(StatusCode, Headers))#{ body => Body }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% method

handle_method(Req, State) ->
    case cowboy_req:method(Req) of
        {<<"POST">>, Req2} ->
            check_authentication(Req2, State);
        {_, Req2} ->
            {response(405), Req2, State}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% authentication

check_authentication(Req, State) ->
    ParseResult = cowboy_req:parse_header(<<"authorization">>, Req, none),
    case handle_parsed_authentication(ParseResult, Req, State) of
        {valid, Req2, State2} ->
            check_form(Req2, State2);
        {invalid, Req2, State2} ->
            {response(401, [failed_auth_prompt_header()]), Req2, State2};
        {bad_header, Req2, State2} ->
            set_result(400, {bad_header, authorization}, Req2, State2)
    end.

handle_parsed_authentication({ok, {<<"basic">>, {Username, Password}}, Req}, _PrevReq, State) ->
    #{ backwater_opts := BackwaterOpts } = State,
    AuthenticatedAccessConfs = maps:get(authenticated_access, BackwaterOpts, #{}),
    validate_authentication(maps:find(Username, AuthenticatedAccessConfs), Password, Req, State);
handle_parsed_authentication({ok, none, Req}, _PrevReq, State) ->
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

default_access_conf(unauthenticated_access) ->
    #{ decode_unsafe_terms => false,
       exposed_modules => [],
       return_exception_stacktraces => false };
default_access_conf(authenticated_access) ->
    #{ decode_unsafe_terms => true,
       exposed_modules => [],
       return_exception_stacktraces => true }.

failed_auth_prompt_header() ->
    {<<"www-authenticate">>, <<"Basic realm=\"backwater\"">>}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% form

check_form(Req, State) ->
    case validate_form(Req, State) of
        {valid, Req2, State2} ->
            check_authorization(Req2, State2);
        {InvalidReason, Req2, State2} ->
            set_result(400, InvalidReason, Req2, State2)
    end.

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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% authorization

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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% existence

check_existence(Req, State) ->
    case find_resource(Req, State) of
        {found, Req2, State2} ->
            check_args_content_type(Req2, State2);
        {NotFound, Req2, State2} ->
            set_result(404, NotFound, Req2, State2)
    end.

find_resource(Req, State) ->
    #{ ref := Ref,
       version := RequiredVersion,
       module := RequiredModule,
       function := RequiredFunction,
       arity := RequiredArity } = State,

    case backwater_module_info:find(Ref, RequiredModule) of
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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% form of arguments content type

check_args_content_type(Req, State) ->
    ParseResult = cowboy_req:parse_header(<<"content-type">>, Req, none),
    case handle_parsed_content_type(ParseResult, Req) of
        {{valid, ContentType}, Req2} ->
            State2 = State#{ args_content_type => ContentType },
            check_accepted_result_content_types(Req2, State2);
        {bad_header, Req2} ->
            set_result(400, {bad_header, 'content-type'}, Req2, State)
    end.

handle_parsed_content_type({ok, ContentType, Req}, _PrevReq) ->
    {{valid, ContentType}, Req};
handle_parsed_content_type({undefined, _Unparsable, Req}, _PrevReq) ->
    {bad_header, Req};
handle_parsed_content_type({error, badarg}, Req) ->
    {bad_header, Req}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% form of accepted result content types

check_accepted_result_content_types(Req, State) ->
    ParseResult = cowboy_req:parse_header(<<"accept">>, Req, []),
    case handle_parsed_accept(ParseResult, Req) of
        {{valid, AcceptedContentTypes}, Req2} ->
            State2 = State#{ accepted_result_content_types => AcceptedContentTypes },
            negotiate_args_content_type(Req2, State2);
        {bad_header, Req2} ->
            set_result(400, {bad_header, accept}, Req2, State)
    end.

handle_parsed_accept({ok, AcceptedContentTypes, Req}, _PrevReq) when is_list(AcceptedContentTypes) > 0 ->
    SortedAcceptedContentTypes = lists:reverse( lists:keysort(2, AcceptedContentTypes) ),
    {{valid, SortedAcceptedContentTypes}, Req};
handle_parsed_accept({undefined, _Unparsable, Req}, _PrevReq) ->
    {bad_header, Req};
handle_parsed_accept({error, badarg}, Req) ->
    {bad_header, Req}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% negotiation of arguments content type

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
        true -> negotiate_result_content_type(Req, State);
        false -> {response(415), Req, State}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% negotiation of results content type

negotiate_result_content_type(Req, State) ->
    #{ function_properties := FunctionProperties,
       accepted_result_content_types := AcceptedContentTypes } = State,
    #{ known_content_types := KnownContentTypes } = FunctionProperties,

    SearchResult =
        lists_anymap(
          fun ({{Type, SubType, _Params}, _Quality, _AcceptExt} = ContentType) ->
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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% read and decode arguments

read_and_decode_args(Req, State) ->
    case cowboy_req:body(Req) of
        {ok, Data, Req2} ->
            decode_args(Data, Req2, State);
        {more, _Data, Req2} ->
            {response(413), Req2, State};
        {error, _Error} ->
            set_result(400, unable_to_read_body, Req, State)
    end.

decode_args(Data, Req, State) ->
    #{ args_content_type := ArgsContentType } = State,
    case ArgsContentType of
        {<<"application">>, <<"x-erlang-etf">>, Params} ->
            decode_etf_args(Params, Data, Req, State)
    end.

decode_etf_args(_Params, Data, Req, State) ->
    % TODO use Params
    #{ access_conf := AccessConf } = State,
    #{ decode_unsafe_terms := DecodeUnsafeTerms } = AccessConf,
    case backwater_codec_etf:decode(Data, DecodeUnsafeTerms) of
        error ->
            %Req3 = set_resp_body({error, undecodable_payload}, Req2),
            set_result(400, unable_to_decode_arguments, Req, State);
        {ok, UnvalidatedArgs} ->
            validate_args(UnvalidatedArgs, Req, State)
    end.

validate_args(UnvalidatedArgs, Req, State)
  when not is_list(UnvalidatedArgs) ->
    set_result(400, arguments_not_a_list, Req, State);
validate_args(UnvalidatedArgs, Req, #{ arity := Arity } = State)
  when length(UnvalidatedArgs) =/= Arity ->
    set_result(400, inconsistent_arguments_arity, Req, State);
validate_args(Args, Req, State) ->
    handle_call(Args, Req, State).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% execute the call

handle_call(Args, Req, State) ->
    #{ access_conf := AccessConf, module := Module, function := Function } = State,
    Result = call_function(Module, Function, Args, AccessConf),
    set_result(200, Result, Req, State).

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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% encode the result

set_result(StatusCode, Result, Req, #{ result_content_type := ResultContentType } = State) ->
    {{Type, SubType, _Params}, _Quality, _AcceptExt} = ResultContentType,
    % TODO use params
    ContentTypeHeader = {<<"content-type">>, <<Type/binary, "/", SubType/binary>>},
    Data = encode_result_body(Result, ResultContentType),
    {response(StatusCode, [ContentTypeHeader], Data), Req, State};
set_result(StatusCode, Result, Req, State) ->
    Data = io_lib:format("~p", [Result]),
    {response(StatusCode, [], Data), Req, State}.

encode_result_body(Result, {{<<"application">>, <<"x-erlang-etf">>, _Params}, _Quality, _AcceptExt}) ->
    % TODO use Params
    backwater_codec_etf:encode(Result).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

utf8bin_to_atom(BinValue, #{ decode_unsafe_terms := true }) ->
    binary_to_atom(BinValue, utf8);
utf8bin_to_atom(BinValue, #{ decode_unsafe_terms := false }) ->
    binary_to_existing_atom(BinValue, utf8).

lists_anymap(_Fun, []) ->
    false;
lists_anymap(Fun, [H|T]) ->
    case Fun(H) of
        {true, MappedH} -> {true, MappedH};
        true -> {true, H};
        false -> lists_anymap(Fun, T)
    end.
