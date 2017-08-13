-module(backwater_SUITE).
-compile(export_all).

-define(CLEAR_PORT, 8080).
-define(TLS_PORT, 8443).

-include_lib("eunit/include/eunit.hrl").

all() ->
    Groups = [{group, GroupName} || {GroupName, _Options, _TestCases} <- groups()],
    all_individual_tests() ++ Groups.

groups() ->
    GroupNames = group_names(),
    [{GroupName, [parallel], all_group_tests()} || GroupName <- GroupNames].

init_per_group(Name, Config) ->
    {ok, _} = application:ensure_all_started(backwater),
    {Endpoint, StartFun, ProtoOpts, HackneyOpts} = get_starting_params(Name),
    Secret = crypto:strong_rand_bytes(32),
    {_Protocol, DecodeUnsafeTerms, ReturnExceptionStacktraces} = decode_group_name(Name),
    ServerConfig =
        #{ secret => Secret,
           exposed_modules =>
                [{erlang, [{exports, all}]},
                 {string, [{exports, all}]},
                 {non_existing_module, [{exports, all}]}],
           decode_unsafe_terms => DecodeUnsafeTerms,
           return_exception_stacktraces => ReturnExceptionStacktraces
         },
    {ok, _Pid} = backwater_server:StartFun(Name, ServerConfig, ProtoOpts, #{}),

    BaseClientConfig =
        #{ endpoint => Endpoint,
           secret => Secret,
           hackney_options => HackneyOpts },
    ok = backwater_client:start(Name, BaseClientConfig),

    ClientConfigWithWrongEndpoint =
        BaseClientConfig#{ endpoint := <<"http://127.0.0.2">> },
    ok = backwater_client:start(
           {wrong_endpoint, Name}, ClientConfigWithWrongEndpoint),

    ClientConfigWithWrongSecret =
        BaseClientConfig#{ secret := crypto:strong_rand_bytes(32) },
    ok = backwater_client:start(
           {wrong_secret, Name}, ClientConfigWithWrongSecret),

    ClientConfigRethrowingRemoteExceptions =
        BaseClientConfig#{ rethrow_remote_exceptions => true },
    ok = backwater_client:start(
           {remote_exceptions_rethrown, Name},
           ClientConfigRethrowingRemoteExceptions),

    [{ref, Name}, {name, Name}, {server_start_fun, StartFun} | Config].

end_per_group(_Name, Config1) ->
    {value, {ref, Ref}, Config2} = lists:keytake(ref, 1, Config1),
    Config3 = lists_keywithout([server_start_fun], 1, Config2),
    ok = backwater_server:stop_listener(Ref),
    ok = backwater_client:stop(Ref),
    Config3.

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(backwater),
    Config.

end_per_suite(Config) ->
    Config.

%%%

bad_client_start_config_test(_Config) ->
    Ref = bad_client_start_config_test,
    StartFun = fun (Config) -> backwater_client:start(Ref, Config) end,

    % not a map
    ?assertEqual({error, invalid_config}, StartFun([])),

    % missing parameters
    ?assertEqual(
       {error, {missing_mandatory_config_parameters, [endpoint, secret]}},
       StartFun(#{})),
    ?assertEqual(
       {error, {missing_mandatory_config_parameters, [secret]}},
       StartFun(#{ endpoint => <<>> })),
    ?assertEqual(
       {error, {missing_mandatory_config_parameters, [endpoint]}},
       StartFun(#{ secret => <<>> })),

    % invalid endpoint
    ?assertEqual(
       {error, {invalid_config_parameter, {endpoint, invalid_endpoint}}},
       StartFun(#{ endpoint => invalid_endpoint, secret => <<>> })),

    % invalid secret
    ?assertEqual(
       {error, {invalid_config_parameter, {secret, invalid_secret}}},
       StartFun(#{ endpoint => <<"https://blah">>, secret => invalid_secret })),

    % invalid hackney_options (optional)
    ?assertEqual(
       {error, {invalid_config_parameter, {hackney_options, invalid_hackney_options}}},
       StartFun(#{ endpoint => <<"https://blah">>, secret => <<>>,
                   hackney_options => invalid_hackney_options })),

    % invalid decode_unsafe_terms (optional)
    ?assertEqual(
       {error, {invalid_config_parameter, {decode_unsafe_terms, invalid_decode_unsafe_terms}}},
       StartFun(#{ endpoint => <<"https://blah">>, secret => <<>>,
                   decode_unsafe_terms => invalid_decode_unsafe_terms })),

    % invalid decode_unsafe_terms (optional)
    ?assertEqual(
       {error, {invalid_config_parameter, {rethrow_remote_exceptions, invalid_rethrow_remote_exceptions}}},
       StartFun(#{ endpoint => <<"https://blah">>, secret => <<>>,
                   rethrow_remote_exceptions => invalid_rethrow_remote_exceptions })),

    % unknown setting
    ?assertEqual(
       {error, {invalid_config_parameter, {unknown_setting, some_value}}},
       StartFun(#{ endpoint => <<"https://blah">>, secret => <<>>,
                   unknown_setting => some_value })).

bad_client_stop_test(_Config) ->
    ?assertEqual({error, not_found}, backwater_client:stop(non_existing_client_ref)).

%%%

bad_server_start_config_grouptest(Config) ->
    {name, Name} = lists:keyfind(name, 1, Config),
    bad_server_start_config_grouptest(Config, Name).

bad_server_start_config_grouptest(Config, Name) ->
    {server_start_fun, StartFun} = lists:keyfind(server_start_fun, 1, Config),
    Ref = {Name, bad_server_start_config_grouptest},
    WrappedStartFun =
        fun (ServerConfig) ->
                backwater_server:StartFun(Ref, ServerConfig, [{port,12345}], #{})
        end,

    % not a map
    ?assertEqual({error, invalid_config}, WrappedStartFun([])),

    % missing opts
    ?assertEqual(
       {error, {missing_mandatory_config_parameters, [exposed_modules, secret]}},
       WrappedStartFun(#{})),
    ?assertEqual(
       {error, {missing_mandatory_config_parameters, [exposed_modules]}},
       WrappedStartFun(#{ secret => <<>> })),
    ?assertEqual(
       {error, {missing_mandatory_config_parameters, [secret]}},
       WrappedStartFun(#{ exposed_modules => [] })),

    % invalid secret
    ?assertEqual(
       {error, {invalid_config_parameter, {secret, invalid_secret}}},
       WrappedStartFun(#{ secret => invalid_secret, exposed_modules => [] })),

    % invalid exposed_modules
    ?assertEqual(
       {error, {invalid_config_parameter, {exposed_modules, invalid_exposed_modules}}},
       WrappedStartFun(#{ secret => <<>>, exposed_modules => invalid_exposed_modules })),

    % invalid decode_unsafe_terms (optional)
    ?assertEqual(
       {error, {invalid_config_parameter, {decode_unsafe_terms, invalid_decode_unsafe_terms}}},
       WrappedStartFun(#{ secret => <<>>, exposed_modules => [],
                          decode_unsafe_terms => invalid_decode_unsafe_terms })),

    % invalid return_exception_stacktraces (optional)
    ?assertEqual(
       {error, {invalid_config_parameter, {return_exception_stacktraces, invalid_return_exception_stacktraces}}},
       WrappedStartFun(#{ secret => <<>>, exposed_modules => [],
                          return_exception_stacktraces => invalid_return_exception_stacktraces })),

    % unknown setting
    ?assertEqual(
       {error, {invalid_config_parameter, {unknown_setting, some_value}}},
       WrappedStartFun(#{ secret => <<>>, exposed_modules => [],
                          unknown_setting => some_value })).

server_start_ref_clash_grouptest(Config) ->
    {name, Name} = lists:keyfind(name, 1, Config),
    {Protocol, _DecodeUnsafeTerms, _ReturnExceptionStacktraces} = decode_group_name(Name),
    server_start_ref_clash_grouptest(Config, Name, Protocol).

server_start_ref_clash_grouptest(_Config, _Name, Protocol) when Protocol =/= http ->
    {skip, not_applicable};
server_start_ref_clash_grouptest(Config, Name, _Protocol) ->
    {server_start_fun, StartFun} = lists:keyfind(server_start_fun, 1, Config),
    Ref = {Name, server_start_ref_clash_test},
    WrappedStartFun =
        fun (ServerConfig) ->
                ProtoOpts = [{port,12346}],
                backwater_server:StartFun(Ref, ServerConfig, ProtoOpts, #{})
        end,

    ?assertMatch(
       {ok, _Pid},
       WrappedStartFun(#{ secret => <<>>, exposed_modules => [] })),
    ?assertMatch(
       {error, {already_started, _Pid}},
       WrappedStartFun(#{ secret => <<>>, exposed_modules => [] })),
    ?assertEqual(
       ok,
       backwater_server:stop_listener(Ref)).

simple_call_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg1 = rand:uniform(1000),
    Arg2 = rand:uniform(1000),
    ExpectedResult = Arg1 * Arg2,
    ?assertEqual({ok, ExpectedResult}, backwater_client:call(Ref, "1", erlang, '*', [Arg1, Arg2])).

compressed_arguments_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = string:copies("foobar", 1000),
    ExpectedResult = length(Arg),
    ?assertEqual({ok, ExpectedResult}, backwater_client:call(Ref, "1", erlang, length, [Arg])).

compressed_result_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg1 = "foobar",
    Arg2 = 1000,
    ExpectedResult = string:copies(Arg1, Arg2),
    ?assertEqual({ok, ExpectedResult}, backwater_client:call(Ref, "1", string, copies, [Arg1, Arg2])).

compressed_argument_and_result_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = string:copies("foobar", 1000),
    ExpectedResult = list_to_binary(Arg),
    ?assertEqual({ok, ExpectedResult}, backwater_client:call(Ref, "1", erlang, list_to_binary, [Arg])).

wrong_endpoint_grouptest(Config) ->
    {ref, BaseRef} = lists:keyfind(ref, 1, Config),
    Ref = {wrong_endpoint, BaseRef},
    Arg = rand:uniform(1000),
    ?assertEqual({error, {hackney,econnrefused}}, backwater_client:call(Ref, "1", erlang, '-', [Arg])).

wrong_secret_grouptest(Config) ->
    {ref, BaseRef} = lists:keyfind(ref, 1, Config),
    Ref = {wrong_secret, BaseRef},
    Arg = rand:uniform(1000),
    ?assertEqual(
       {error, {{response_authentication, missing_request_id},  % local error
                {unauthorized, <<"invalid_signature">>}}},      % remote error
       backwater_client:call(Ref, "1", erlang, '-', [Arg])).

wrong_request_auth_type_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
           #{ {update_headers_with, final} =>
                update_header_fun(<<"authorization">>, <<"Basic blahblah">>) } },
    ?assertEqual(
       {error, {{response_authentication, missing_request_id},  % local error
                {unauthorized, <<"invalid_auth_type">>}}},      % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

malformed_request_auth_not_params_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
           #{ {update_headers_with, final} =>
                update_header_fun(<<"authorization">>, <<"Signature blahblah;=;=;">>) } },
    ?assertEqual(
       {error, {{response_authentication, missing_request_id},  % local error
                {unauthorized, <<"invalid_header_params">>}}},  % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

malformed_request_auth_badly_quoted_params_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
           #{ {update_headers_with, final} =>
                update_header_fun(<<"authorization">>, <<"Signature blah=">>) } },
    ?assertEqual(
       {error, {{response_authentication, missing_request_id},  % local error
                {unauthorized, <<"invalid_header_params">>}}},  % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

missing_request_auth_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, final} => remove_header_fun(<<"authorization">>) } },
    ?assertEqual(
       {error, {{response_authentication, missing_request_id},        % local error
                {unauthorized, <<"missing_authorization_header">>}}}, % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

missing_request_digest_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, final} => remove_header_fun(<<"digest">>) } },
    ?assertEqual(
       {error, {{response_authentication, missing_request_id},           % local error
                {unauthorized, <<"{missing_header,<<\"digest\">>}">>}}}, % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

missing_request_request_id_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, final} => remove_header_fun(<<"x-request-id">>) } },
    ?assertEqual(
       {error, {{response_authentication, missing_request_id},                 % local error
                {unauthorized, <<"{missing_header,<<\"x-request-id\">>}">>}}}, % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

negative_url_arity_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"-1">>, -1) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id}, % local error
                {not_found, _}}},                              % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

big_url_arity_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"256">>, -1) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id}, % local error
                {not_found, _}}},                              % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

nonnumeric_url_arity_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"foobar">>, -1) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id}, % local error
                {not_found, _}}},                              % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

nonutf8_url_module_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"ê">>, -3) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id}, % local error
                {not_found, _}}},                              % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

nonutf8_url_function_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"ê">>, -2) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id}, % local error
                {not_found, _}}},                              % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

big_url_module_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    BinModule = list_to_binary( string:copies("x", 256) ),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(BinModule, -3) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id}, % local error
                {not_found, _}}},                              % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

big_url_function_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    BinFunction = list_to_binary( string:copies("x", 256) ),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(BinFunction, -2) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id}, % local error
                {not_found, _}}},                              % remote error
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

unallowed_method_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_method_with => value_fun1(<<"GET">>) } },
    ?assertMatch(
       {error, {remote_error, {method_not_allowed, _}}},
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

unauthorized_module_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {remote_error, {forbidden, _}}},
       backwater_client:call(Ref, "1", erlangsssss, '-', [Arg])).

non_existing_module_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {remote_error, {not_found, _}}},
       backwater_client:call(Ref, "1", non_existing_module, '-', [Arg])).

non_existing_module_version_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {remote_error, {not_found, _}}},
       backwater_client:call(Ref, "2", erlang, '-', [Arg])).

non_existing_function_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {remote_error, {not_found, _}}},
       backwater_client:call(Ref, "1", erlang, '-----', [Arg])).

unsupported_content_type_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, before_compression} =>
                    update_header_fun(<<"content-type">>, <<"text/plain">>) } },
    ?assertMatch(
       {error, {remote_error, {unsupported_media_type, <<"unsupported_content_type">>}}},
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

unsupported_content_encoding_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, before_authentication} =>
                    update_header_fun(<<"content-encoding">>, <<"deflate">>) } },
    ?assertMatch(
       {error, {remote_error, {unsupported_media_type, <<"unsupported_content_encoding">>}}},
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

unsupported_accepted_content_encoding_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, before_compression} =>
                    update_header_fun(<<"accept">>, <<"text/plain">>) } },
    ?assertMatch(
       {error, {remote_error, {not_acceptable, <<>>}}},
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

malformed_request_body_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_body_with, before_compression} =>
                    value_fun1(crypto:strong_rand_bytes(100)) } },
    ?assertMatch(
       {error, {remote_error, {bad_request, unable_to_decode_arguments}}},
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

malformed_compressed_request_body_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = string:copies("foobar", 1000),
    Override =
        #{ request =>
            #{ {update_body_with, before_authentication} =>
                    value_fun1(crypto:strong_rand_bytes(100)) } },
    ?assertMatch(
       {error, {remote_error, {bad_request, unable_to_uncompress_arguments}}},
       backwater_client:'_call'(Ref, "1", erlang, length, [Arg], Override)).

inconsistent_arguments_arity_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_arity_with => value_fun1(2) } },
    ?assertMatch(
       {error, {remote_error, {bad_request, inconsistent_arguments_arity}}},
       backwater_client:'_call'(Ref, "1", erlang, '-', [Arg], Override)).

exception_error_result_grouptest(Config) ->
    {name, Name} = lists:keyfind(name, 1, Config),
    {_Protocol, _DecodeUnsafeTerms, ReturnExceptionStacktraces} = decode_group_name(Name),
    exception_error_result_grouptest(Config, ReturnExceptionStacktraces).

exception_error_result_grouptest(Config, ReturnExceptionStacktraces) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg1 = rand:uniform(1000),
    Arg2 = 0,
    case ReturnExceptionStacktraces of
        true ->
            ?assertMatch(
               {error, {remote_exception, error, badarith, [{erlang,'/',[Arg1, Arg2], _}]}},
               backwater_client:call(Ref, "1", erlang, '/', [Arg1, Arg2]));
        false ->
            ?assertMatch(
               {error, {remote_exception, error, badarith, []}},
               backwater_client:call(Ref, "1", erlang, '/', [Arg1, Arg2]))
    end.

unsafe_argument_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    {name, Name} = lists:keyfind(name, 1, Config),
    {_Protocol, DecodeUnsafeTerms, _ReturnExceptionStacktraces} = decode_group_name(Name),
    AtomName = base64:encode( crypto:strong_rand_bytes(16) ),
    AtomNameSize = byte_size(AtomName),
    Arity = 2,
    EncodedArguments = <<131, 108, Arity:32,                 % list tag and size
                         119, AtomNameSize, AtomName/binary, % argument 1 (encoded atom)
                         119, 4, "utf8",                     % argument 2 (encoded atom)
                         106>>,                              % list termination (nil)
    Override =
        #{ request =>
            #{ {update_body_with, before_authentication} => value_fun1(EncodedArguments) } },

    Result = backwater_client:'_call'(Ref, "1", erlang, atom_to_binary, [placeholder, utf8], Override),
    case DecodeUnsafeTerms of
        true ->
            ?assertEqual({ok, AtomName}, Result);
        false ->
            ?assertEqual(
               {error, {remote_error, {bad_request, unable_to_decode_arguments}}},
               Result)
    end.

%%%
all_individual_tests() ->
    [Name || {Name, 1} <- exported_functions(),
             lists:suffix("_test", atom_to_list(Name))].

all_group_tests() ->
    [Name || {Name, 1} <- exported_functions(),
             lists:suffix("_grouptest", atom_to_list(Name))].

group_names() ->
    [encode_group_name(Protocol, DecodeUnsafeTerms, ReturnExceptionStacktraces)
     || Protocol <- [http, https],
        DecodeUnsafeTerms <- [true, false],
        ReturnExceptionStacktraces <- [true, false]].

encode_group_name(Protocol, DecodeUnsafeTerms, ReturnExceptionStacktraces) ->
    Parts =
        lists:map(
          fun atom_to_list/1,
          [Protocol,
           encode_decode_unsafe_terms_value(DecodeUnsafeTerms),
           encode_return_exception_stacktraces_value(ReturnExceptionStacktraces)]),
    Joined = lists:join("__", Parts),
    Flattened = lists:foldr(fun string:concat/2, "", Joined),
    list_to_atom(Flattened).

decode_group_name(Atom) ->
    Binary = atom_to_binary(Atom, utf8),
    Parts = binary:split(Binary, <<"__">>, [global]),
    AtomParts = [binary_to_atom(Part, utf8) || Part <- Parts],
    [Protocol, EncodedDecodeUnsafeTerms, EncodedReturnExceptionStacktraces] = AtomParts,
    {Protocol,
     decode_decode_unsafe_terms_value(EncodedDecodeUnsafeTerms),
     decode_return_exception_stacktraces_value(EncodedReturnExceptionStacktraces)}.

encode_decode_unsafe_terms_value(true) -> unsafe_decode;
encode_decode_unsafe_terms_value(false) -> safe_decode.

decode_decode_unsafe_terms_value(unsafe_decode) -> true;
decode_decode_unsafe_terms_value(safe_decode) -> false.

encode_return_exception_stacktraces_value(true) -> with_exc_stacktraces;
encode_return_exception_stacktraces_value(false) -> without_exc_stacktraces.

decode_return_exception_stacktraces_value(with_exc_stacktraces) -> true;
decode_return_exception_stacktraces_value(without_exc_stacktraces) -> false.

exported_functions() ->
    ModuleInfo = ?MODULE:module_info(),
    {exports, Exports} = lists:keyfind(exports, 1, ModuleInfo),
    Exports.

get_starting_params(GroupName) ->
    {Protocol, _DecodeUnsafeTerms, _ReturnExceptionStacktraces} = decode_group_name(GroupName),
    get_starting_params_(Protocol).

get_starting_params_(http) ->
    Port = ?CLEAR_PORT,
    Endpoint = <<"http://127.0.0.1:", (integer_to_binary(Port))/binary>>,
    ProtoOpts = [{port, Port}],
    HackneyOpts = [],
    {Endpoint, start_clear, ProtoOpts, HackneyOpts};
get_starting_params_(https) ->
    Port = ?TLS_PORT,
    Endpoint = <<"https://127.0.0.1:", (integer_to_binary(Port))/binary>>,
    ProtoOpts =
        [{port, Port},
         {certfile, ssl_certificate_path()},
         {keyfile, ssl_key_path()}],
    HackneyOpts =
        [insecure],
    {Endpoint, start_tls, ProtoOpts, HackneyOpts}.

ssl_certificate_path() ->
    Path = filename:join([source_directory(), "data", "ssl"]),
    filename:join(Path, "server.crt").

ssl_key_path() ->
    Path = filename:join([source_directory(), "data", "ssl"]),
    filename:join(Path, "server.key").

source_directory() ->
    % very dirty hack
    ModuleInfo = ?MODULE:module_info(),
    {compile, CompileOptions} = lists:keyfind(compile, 1, ModuleInfo),
    {source, Source} = lists:keyfind(source, 1, CompileOptions),
    filename:dirname(Source).

remove_header_fun(CiName) ->
    fun (CiHeaders) -> lists:keydelete(CiName, 1, CiHeaders) end.

update_header_fun(CiName, Value) ->
    fun (CiHeaders) -> lists:keystore(CiName, 1, CiHeaders, {CiName, Value}) end.

replace_url_part_fun(UpdatedValue, Index) ->
    fun (Url) ->
        Parts = binary:split(Url, <<"/">>, [global]),
        CanonIndex =
            if Index < 0 ->
                   length(Parts) + (Index + 1);
               true ->
                   Index
            end,
        {Left, [_PrevValue | Right]} = lists:split(CanonIndex - 1, Parts),
        UpdatedParts = Left ++ [UpdatedValue | Right],
        list_to_binary(lists:join("/", UpdatedParts))
    end.

value_fun1(Value) ->
    fun (_) -> Value end.

lists_keywithout(Keys, N, List) ->
    lists:foldl(
      fun (Key, Acc) -> lists:keydelete(Key, N, Acc) end,
      List, Keys).