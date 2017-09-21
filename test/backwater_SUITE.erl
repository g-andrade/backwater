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

-module(backwater_SUITE).
-compile(export_all).

-define(CLEAR_PORT, 8080).
-define(TLS_PORT, 8443).

-include("backwater_SUITE.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [{group, GroupName} || {GroupName, _Options, _TestCases} <- groups()].

groups() ->
    GroupNames = group_names(),
    [{individual_tests, [parallel, shuffle], all_individual_tests()}
     | [{GroupName, [parallel, shuffle], all_group_tests()} || GroupName <- GroupNames]].

init_per_group(individual_tests, Config) ->
    {ok, _} = application:ensure_all_started(backwater),
    Config;
init_per_group(Name, Config) ->
    {ok, _} = application:ensure_all_started(backwater),
    {Endpoint, StartFun, TransportOpts, HackneyOpts} = get_starting_params(Name),
    Secret = crypto:strong_rand_bytes(32),
    {_Protocol, DecodeUnsafeTerms, ReturnExceptionStacktraces,
     UseListProtoOptions} = decode_group_name(Name),
    ServerConfig =
        #{ secret => Secret,
           exposed_modules =>
                [{erlang, [{exports, all}]},
                 {string, [{exports, [{copies,2}]}]},
                 non_existing_module,
                 module_with_backwater_attributes],
           decode_unsafe_terms => DecodeUnsafeTerms,
           return_exception_stacktraces => ReturnExceptionStacktraces
         },
    ProtoOpts =
        case UseListProtoOptions of
            true -> [];
            false -> #{}
        end,
    {ok, _Pid} = backwater_server:StartFun(Name, ServerConfig, TransportOpts, ProtoOpts),

    BaseClientConfig =
        #{ endpoint => Endpoint,
           secret => Secret,
           hackney_opts => HackneyOpts },
    ok = backwater_client:start(Name, BaseClientConfig),

    ClientConfigWithWrongEndpoint =
        BaseClientConfig#{ endpoint := <<Endpoint/binary, "/nope">> },
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

end_per_group(individual_tests, Config) ->
    _ = application:stop(backwater),
    _ = application:stop(cowboy),
    Config;
end_per_group(_Name, Config1) ->
    {value, {ref, Ref}, Config2} = lists:keytake(ref, 1, Config1),
    Config3 = lists_keywithout([server_start_fun, name], 1, Config2),
    ok = backwater_server:stop_listener(Ref),
    lists:foreach(
      fun backwater_client:stop/1,
      [Ref,
       {wrong_endpoint, Ref},
       {wrong_secret, Ref},
       {remote_exceptions_rethrown, Ref}]),
    _ = application:stop(backwater),
    _ = application:stop(cowboy),
    Config3.

%%%

bad_client_start_config_test(_Config) ->
    Ref = bad_client_start_config_test,
    StartFun = fun (Config) -> backwater_client:start(Ref, Config) end,

    % not a map
    ?assertEqual({error, config_not_a_map}, StartFun([])),

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

    % invalid hackney_opts (optional)
    ?assertEqual(
       {error, {invalid_config_parameter, {hackney_opts, invalid_hackney_opts}}},
       StartFun(#{ endpoint => <<"https://blah">>, secret => <<>>,
                   hackney_opts => invalid_hackney_opts })),

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
                   unknown_setting => some_value })),

    % already started
    ?assertEqual(
       ok,
       StartFun(#{ endpoint => <<"https://blah">>, secret => <<>> })),
    ?assertEqual(
       {error, already_started},
       StartFun(#{ endpoint => <<"https://blah">>, secret => <<>> })),

    ?assertEqual(ok, backwater_client:stop(Ref)).

not_started_client_stop_test(_Config) ->
    ?assertEqual({error, not_found}, backwater_client:stop(non_existing_client_ref)).

not_started_client_call_test(_Config) ->
    ?assertEqual(
       {error, not_started},
       backwater_client:call(non_existing_client_ref, erlang, self, [])).

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
    ?assertEqual({error, config_not_a_map}, WrappedStartFun([])),

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
    {Protocol, _DecodeUnsafeTerms, _ReturnExceptionStacktraces,
     _UseListProtoOptions} = decode_group_name(Name),
    server_start_ref_clash_grouptest(Config, Name, Protocol).

server_start_ref_clash_grouptest(_Config, _Name, Protocol) when Protocol =/= http ->
    {skip, not_applicable};
server_start_ref_clash_grouptest(Config, Name, _Protocol) ->
    {server_start_fun, StartFun} = lists:keyfind(server_start_fun, 1, Config),
    Ref = {Name, server_start_ref_clash_test},
    WrappedStartFun =
        fun (ServerConfig) ->
                TransportOpts = [{port,12346}],
                backwater_server:StartFun(Ref, ServerConfig, TransportOpts, #{})
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
    ?assertEqual({ok, ExpectedResult}, backwater_client:call(Ref, erlang, '*', [Arg1, Arg2])).

compressed_arguments_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = ?STRING_COPIES_FOOBAR_1000,
    ExpectedResult = length(Arg),
    ?assertEqual({ok, ExpectedResult}, backwater_client:call(Ref, erlang, length, [Arg])).

compressed_result_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg1 = "foobar",
    Arg2 = 1000,
    ExpectedResult = ?STRING_COPIES_FOOBAR_1000,
    ?assertEqual({ok, ExpectedResult}, backwater_client:call(Ref, string, copies, [Arg1, Arg2])).

compressed_argument_and_result_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = ?STRING_COPIES_FOOBAR_1000,
    ExpectedResult = list_to_binary(Arg),
    ?assertEqual({ok, ExpectedResult}, backwater_client:call(Ref, erlang, list_to_binary, [Arg])).

wrong_endpoint_grouptest(Config) ->
    {ref, BaseRef} = lists:keyfind(ref, 1, Config),
    Ref = {wrong_endpoint, BaseRef},
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {not_found, _Headers, _Body}}},
       backwater_client:call(Ref, erlang, '-', [Arg])).

wrong_secret_grouptest(Config) ->
    {ref, BaseRef} = lists:keyfind(ref, 1, Config),
    Ref = {wrong_secret, BaseRef},
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"invalid_signature">>}}},
       backwater_client:call(Ref, erlang, '-', [Arg])).

wrong_request_auth_type_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
           #{ {update_headers_with, final} =>
                update_header_fun(<<"authorization">>, <<"Basic blahblah">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"invalid_auth_type">>}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

malformed_request_auth_not_params_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
           #{ {update_headers_with, final} =>
                update_header_fun(<<"authorization">>, <<"Signature blahblah;=;=;">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"invalid_header_params">>}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

malformed_request_auth_badly_quoted_params_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
           #{ {update_headers_with, final} =>
                update_header_fun(<<"authorization">>, <<"Signature blah=">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"invalid_header_params">>}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

missing_request_auth_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, final} => remove_header_fun(<<"authorization">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"missing_authorization_header">>}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

missing_request_digest_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, final} => remove_header_fun(<<"digest">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"{missing_header,<<\"digest\">>}">>}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

missing_request_request_id_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, final} => remove_header_fun(<<"x-request-id">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"{missing_header,<<\"x-request-id\">>}">>}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

invalid_path_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => append_to_binary_fun(<<"/blah">>) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

negative_url_arity_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"-1">>, -1) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

big_url_arity_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"256">>, -1) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _body}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

nonnumeric_url_arity_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"foobar">>, -1) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

unallowed_method_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_method_with => value_fun1(<<"GET">>) } },
    ?assertMatch(
       {error, {remote, {method_not_allowed, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

unauthorized_module_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {remote, {forbidden, _Headers, _Body}}},
       backwater_client:call(Ref, erlangsssss, '-', [Arg])).

non_existing_module_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {remote, {not_found, _Headers, _Body}}},
       backwater_client:call(Ref, non_existing_module, '-', [Arg])).

non_existing_function_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {remote, {not_found, _Headers, _Body}}},
       backwater_client:call(Ref, erlang, '-----', [Arg])).

unsupported_content_type_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, before_compression} =>
                    update_header_fun(<<"content-type">>, <<"text/plain">>) } },
    ?assertMatch(
       {error, {remote, {unsupported_media_type, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

unsupported_content_encoding_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, before_authentication} =>
                    update_header_fun(<<"content-encoding">>, <<"deflate">>) } },
    ?assertMatch(
       {error, {remote, {unsupported_media_type, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

unsupported_accepted_content_encoding_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, before_compression} =>
                    update_header_fun(<<"accept">>, <<"text/plain">>) } },
    ?assertMatch(
       {error, {remote, {not_acceptable, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

malformed_arguments_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_body_with, before_compression} =>
                    value_fun1(crypto:strong_rand_bytes(100)) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

malformed_compressed_arguments_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = ?STRING_COPIES_FOOBAR_1000,
    Override =
        #{ request =>
            #{ {update_body_with, before_authentication} =>
                    value_fun1(crypto:strong_rand_bytes(100)) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, length, [Arg], Override)).

-ifdef(RUNNING_ON_TRAVIS_CI).
maliciously_compressed_arguments_grouptest(_Config) ->
    {skip, travis_ci_doesnt_like_this}.
-else.
maliciously_compressed_arguments_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    % try to work around request and response limits by compressing when encoding
    EncodedArguments = term_to_binary([?ZEROES_PAYLOAD_20MiB], [compressed]),
    Override =
        #{ request =>
            #{ {update_body_with, before_compression} => value_fun1(EncodedArguments) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, length, [dummy], Override)).
-endif.

inconsistent_arguments_arity_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_arity_with => value_fun1(2) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [Arg], Override)).

wrong_arguments_type_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    EncodedArguments = term_to_binary({}), % tuple instead of list
    Override =
        #{ request =>
            #{ {update_body_with,before_compression} => value_fun1(EncodedArguments) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [dummy], Override)).

wrong_arguments_digest_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    DummyArg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_body_with, final} =>
                    fun (RealBody) ->
                            crypto:strong_rand_bytes( byte_size(RealBody) )
                    end} },
    ?assertMatch(
       {error, {remote, {unauthorized, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [DummyArg], Override)).

-ifdef(RUNNING_ON_TRAVIS_CI).
too_big_arguments_grouptest(_Config) ->
    {skip, travis_ci_doesnt_like_this}.
-else.
too_big_arguments_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    DummyArg = rand:uniform(1000),
    EncodedArguments = ?ZEROES_PAYLOAD_20MiB,
    Override =
        #{ request =>
            #{ {update_body_with, before_authentication} => value_fun1(EncodedArguments) } },
    ?assertMatch(
       {error, {remote, {payload_too_large, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [DummyArg], Override)).
-endif.

-ifdef(RUNNING_ON_TRAVIS_CI).
too_big_compressed_arguments_grouptest(_Config) ->
    {skip, travis_ci_doesnt_like_this}.
-else.
too_big_compressed_arguments_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    DummyArg = rand:uniform(1000),
    EncodedArguments = ?ZEROES_PAYLOAD_20MiB,
    Override =
        #{ request =>
            #{ {update_body_with, before_compression} => value_fun1(EncodedArguments) } },
    ?assertMatch(
       {error, {remote, {payload_too_large, _Headers, _Body}}},
       backwater_client:'_call'(Ref, erlang, '-', [DummyArg], Override)).
-endif.

exception_error_result_grouptest(Config) ->
    {name, Name} = lists:keyfind(name, 1, Config),
    {_Protocol, _DecodeUnsafeTerms, ReturnExceptionStacktraces,
     _UseListProtoOptions} = decode_group_name(Name),
    exception_error_result_grouptest(Config, ReturnExceptionStacktraces).

exception_error_result_grouptest(Config, ReturnExceptionStacktraces) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    Arg1 = rand:uniform(1000),
    Arg2 = 0,
    case ReturnExceptionStacktraces of
        true ->
            ?assertMatch(
               {error, {exception, {error, badarith, [{erlang,'/',[Arg1, Arg2], _}]}}},
               backwater_client:call(Ref, erlang, '/', [Arg1, Arg2]));
        false ->
            ?assertMatch(
               {error, {exception, {error, badarith, []}}},
               backwater_client:call(Ref, erlang, '/', [Arg1, Arg2]))
    end.

exception_throwing_result_grouptest(Config) ->
    {name, Name} = lists:keyfind(name, 1, Config),
    {_Protocol, _DecodeUnsafeTerms, ReturnExceptionStacktraces,
     _UseListProtoOptions} = decode_group_name(Name),
    exception_throwing_result_grouptest(Config, ReturnExceptionStacktraces).

exception_throwing_result_grouptest(Config, ReturnExceptionStacktraces) ->
    {ref, BaseRef} = lists:keyfind(ref, 1, Config),
    Ref = {remote_exceptions_rethrown, BaseRef},
    Arg1 = rand:uniform(1000),
    Arg2 = 0,
    CaughtResult = (catch backwater_client:call(Ref, erlang, '/', [Arg1, Arg2])),
    case ReturnExceptionStacktraces of
        true ->
            ?assertMatch(
               {'EXIT', {badarith, [{erlang, '/', [Arg1, Arg2], _}]}},
               CaughtResult);
        false ->
            ?assertMatch(
               {'EXIT', {badarith, []}},
               CaughtResult)
    end.

unsafe_argument_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),
    {name, Name} = lists:keyfind(name, 1, Config),
    {_Protocol, DecodeUnsafeTerms, _ReturnExceptionStacktraces,
     _UseListProtoOptions} = decode_group_name(Name),
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

    Result = backwater_client:'_call'(Ref, erlang, atom_to_binary, [placeholder, utf8], Override),
    case DecodeUnsafeTerms of
        true ->
            ?assertEqual({ok, AtomName}, Result);
        false ->
            ?assertMatch({error, {remote, {bad_request, _Headers, _Body}}}, Result)
    end.

backwater_attributes_exported_grouptest(Config) ->
    {ref, Ref} = lists:keyfind(ref, 1, Config),

    % exported both regularly and through backwater attribute
    ?assertEqual(
       {ok, {foobar}},
       backwater_client:call(Ref, module_with_backwater_attributes, 'exported_functionA',
                             [])),

    % exported only regularly
    ArgB = rand:uniform(1000),
    ?assertMatch(
       {error, {remote, {not_found, _Headers, _Body}}},
       backwater_client:call(Ref, module_with_backwater_attributes, 'exported_functionB',
                             [ArgB])),

    % exported both regularly and through backwater attribute
    ?assertEqual(
       {ok, {barfoo}},
       backwater_client:call(Ref, module_with_backwater_attributes, 'exported_functionC',
                             [])),

    % exported both regularly and through backwater attribute
    ArgD = rand:uniform(1000),
    ?assertEqual(
       {ok, {ArgD}},
       backwater_client:call(Ref, module_with_backwater_attributes, 'exported_functionD',
                             [ArgD])),

    % exported only through backwater attribute
    ?assertMatch(
       {error, {remote, {not_found, _Headers, _Body}}},
       backwater_client:call(Ref, module_with_backwater_attributes, 'exported_functionE',
                             [])),

    ArgInternal = rand:uniform(1000),
    % existing internal function
    ?assertMatch(
       {error, {remote, {not_found, _Headers, _Body}}},
       backwater_client:call(Ref, module_with_backwater_attributes, 'internal_function',
                             [ArgInternal])).

%%%
all_individual_tests() ->
    [Name || {Name, 1} <- exported_functions(),
             lists:suffix("_test", atom_to_list(Name))].

all_group_tests() ->
    [Name || {Name, 1} <- exported_functions(),
             lists:suffix("_grouptest", atom_to_list(Name))].

group_names() ->
    [encode_group_name(Protocol, DecodeUnsafeTerms, ReturnExceptionStacktraces, UseListProtoOptions)
     || Protocol <- [http, https],
        DecodeUnsafeTerms <- [true, false],
        ReturnExceptionStacktraces <- [true, false],
        UseListProtoOptions <- [true, false]].

encode_group_name(Protocol, DecodeUnsafeTerms, ReturnExceptionStacktraces, UseListProtoOptions) ->
    Parts =
        lists:map(
          fun atom_to_list/1,
          [Protocol,
           encode_decode_unsafe_terms_value(DecodeUnsafeTerms),
           encode_return_exception_stacktraces_value(ReturnExceptionStacktraces),
           encode_use_list_proto_options(UseListProtoOptions)]),
    Joined = lists:join("__", Parts),
    Flattened = lists:foldr(fun string:concat/2, "", Joined),
    list_to_atom(Flattened).

decode_group_name(Atom) ->
    Binary = atom_to_binary(Atom, utf8),
    Parts = binary:split(Binary, <<"__">>, [global]),
    AtomParts = [binary_to_atom(Part, utf8) || Part <- Parts],
    [Protocol, EncodedDecodeUnsafeTerms, EncodedReturnExceptionStacktraces,
     EncodedUseListProtoOptions] = AtomParts,
    {Protocol,
     decode_decode_unsafe_terms_value(EncodedDecodeUnsafeTerms),
     decode_return_exception_stacktraces_value(EncodedReturnExceptionStacktraces),
     decode_use_list_proto_options(EncodedUseListProtoOptions)}.

encode_decode_unsafe_terms_value(true) -> unsafe_decode;
encode_decode_unsafe_terms_value(false) -> safe_decode.

decode_decode_unsafe_terms_value(unsafe_decode) -> true;
decode_decode_unsafe_terms_value(safe_decode) -> false.

encode_return_exception_stacktraces_value(true) -> with_exc_stacktraces;
encode_return_exception_stacktraces_value(false) -> without_exc_stacktraces.

decode_return_exception_stacktraces_value(with_exc_stacktraces) -> true;
decode_return_exception_stacktraces_value(without_exc_stacktraces) -> false.

encode_use_list_proto_options(true) -> list_proto_options;
encode_use_list_proto_options(false) -> map_proto_options.

decode_use_list_proto_options(list_proto_options) -> true;
decode_use_list_proto_options(map_proto_options) -> false.

exported_functions() ->
    ModuleInfo = ?MODULE:module_info(),
    {exports, Exports} = lists:keyfind(exports, 1, ModuleInfo),
    Exports.

get_starting_params(GroupName) ->
    {Protocol, _DecodeUnsafeTerms, _ReturnExceptionStacktraces,
     _UseListProtoOptions} = decode_group_name(GroupName),
    get_starting_params_(Protocol).

get_starting_params_(http) ->
    Port = ?CLEAR_PORT,
    Endpoint = <<"http://127.0.0.1:", (integer_to_binary(Port))/binary>>,
    TransportOpts = [{port, Port}, {num_acceptors, 50}],
    HackneyOpts = [],
    {Endpoint, start_clear, TransportOpts, HackneyOpts};
get_starting_params_(https) ->
    Port = ?TLS_PORT,
    Endpoint = <<"https://127.0.0.1:", (integer_to_binary(Port))/binary>>,
    TransportOpts =
        [{port, Port},
         {certfile, ssl_certificate_path()},
         {keyfile, ssl_key_path()},
         {num_acceptors, 50}],
    HackneyOpts =
        [insecure,
         {ssl_options, [{server_name_indication, disable}]}],
    {Endpoint, start_tls, TransportOpts, HackneyOpts}.

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

append_to_binary_fun(Suffix) ->
    fun (Binary) -> <<Binary/binary, Suffix/binary>> end.

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
