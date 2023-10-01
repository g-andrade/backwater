%% Copyright (c) 2017-2022 Guilherme Andrade <backwater@gandrade.net>
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
    [{GroupName, [parallel], all_group_tests()} || GroupName <- GroupNames].

init_per_group(Name, Config) ->
    {ok, _} = application:ensure_all_started(backwater),
    {Location, StartFun, TransportOpts, HackneyOpts} = get_starting_params(Name),
    Secret = crypto:strong_rand_bytes(32),
    {_Protocol, DecodeUnsafeTerms, ReturnExceptionStacktraces} = decode_group_name(Name),
    ExposedModules =
        [erlang,
         {string, [{exports, [{copies,2}]}]},
         non_existing_module
        ],
    ServerOptions =
        #{ transport => TransportOpts,
           %http => #{},
           backwater =>
                #{ decode_unsafe_terms => DecodeUnsafeTerms,
                   return_exception_stacktraces => ReturnExceptionStacktraces
                 }
         },
    {ok, _Pid} = backwater:StartFun(Name, Secret, ExposedModules, ServerOptions),

    ClientEndpoint = {Location, Secret},
    ClientOptions = #{ hackney_opts => HackneyOpts },

    [{ref, Name}, {name, Name}, {server_start_fun, StartFun},
     {client_endpoint, ClientEndpoint}, {client_options, ClientOptions}
     | Config].

end_per_group(_Name, Config1) ->
    {value, {ref, Ref}, Config2} = lists:keytake(ref, 1, Config1),
    Config3 = lists_keywithout([server_start_fun, name], 1, Config2),
    ok = backwater:stop_server(Ref),
    _ = application:stop(backwater),
    _ = application:stop(cowboy),
    Config3.

%%%

bad_server_start_config_grouptest(Config) ->
    {name, Name} = lists:keyfind(name, 1, Config),
    bad_server_start_config_grouptest(Config, Name).

bad_server_start_config_grouptest(Config, Name) ->
    {server_start_fun, StartFun} = lists:keyfind(server_start_fun, 1, Config),
    Ref = {Name, bad_server_start_config_grouptest},
    WrappedStartFun =
        fun (Secret, ExposedModules, BackwaterOptions) ->
                ServerOptions =
                    #{ transport => [{port,12345}],
                       backwater => BackwaterOptions },
                backwater:StartFun(Ref, Secret, ExposedModules, ServerOptions)
        end,

    % not a map
    ?assertEqual({error, options_not_a_map}, WrappedStartFun(<<>>, [], [])),

    % invalid secret
    ?assertEqual(
       {error, invalid_secret},
       WrappedStartFun(not_a_secret, [], #{})),

    % invalid exposed_modules
    ?assertEqual(
       {error, invalid_exposed_modules},
       WrappedStartFun(<<>>, not_exposed_modules, #{})),

    % invalid decode_unsafe_terms option
    ?assertEqual(
       {error, {invalid_config_parameter, {decode_unsafe_terms, invalid_decode_unsafe_terms}}},
       WrappedStartFun(<<>>, [], #{ decode_unsafe_terms => invalid_decode_unsafe_terms })),

    % invalid return_exception_stacktraces option
    ?assertEqual(
       {error, {invalid_config_parameter, {return_exception_stacktraces, invalid_return_exception_stacktraces}}},
       WrappedStartFun(<<>>, [], #{ return_exception_stacktraces => invalid_return_exception_stacktraces })),

    % unknown option
    ?assertEqual(
       {error, {invalid_config_parameter, {unknown_setting, some_value}}},
       WrappedStartFun(<<>>, [], #{ unknown_setting => some_value })).

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
        fun (Secret, ExposedModules, BackwaterOptions) ->
                ServerOptions =
                    #{ transport => [{port,12346}],
                       backwater => BackwaterOptions },
                backwater:StartFun(Ref, Secret, ExposedModules, ServerOptions)
        end,

    ?assertMatch(
       {ok, _Pid},
       WrappedStartFun(<<>>, [], #{})),
    ?assertMatch(
       {error, {already_started, _Pid}},
       WrappedStartFun(<<>>, [], #{})),
    ?assertEqual(
       ok,
       backwater:stop_server(Ref)).

escaped_function_name_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg1 = rand:uniform(1000),
    Arg2 = rand:uniform(1000),
    ExpectedResult = Arg1 * Arg2,
    ?assertEqual({ok, ExpectedResult},
                 backwater:call(Endpoint, erlang, '*', [Arg1, Arg2], Options)).

compressed_arguments_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = ?STRING_COPIES_FOOBAR_1000,
    ExpectedResult = length(Arg),
    ?assertEqual({ok, ExpectedResult},
                 backwater:call(Endpoint, erlang, length, [Arg], Options)).

compressed_result_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg1 = "foobar",
    Arg2 = 1000,
    ExpectedResult = ?STRING_COPIES_FOOBAR_1000,
    ?assertEqual({ok, ExpectedResult},
                 backwater:call(Endpoint, string, copies, [Arg1, Arg2], Options)).

compressed_argument_and_result_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = ?STRING_COPIES_FOOBAR_1000,
    ExpectedResult = list_to_binary(Arg),
    ?assertEqual({ok, ExpectedResult},
                 backwater:call(Endpoint, erlang, list_to_binary, [Arg], Options)).

wrong_location_grouptest(Config) ->
    {client_endpoint, {ValidLocation, Secret}} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    InvalidLocation = <<ValidLocation/binary, "/nope">>,
    Endpoint = {InvalidLocation, Secret},
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {not_found, _Headers, _Body}}},
       backwater:call(Endpoint, erlang, '-', [Arg], Options)).

wrong_secret_grouptest(Config) ->
    {client_endpoint, {Location, _ValidSecret}} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    InvalidSecret = crypto:strong_rand_bytes(32),
    Endpoint = {Location, InvalidSecret},
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"invalid_signature">>}}},
       backwater:call(Endpoint, erlang, '-', [Arg], Options)).

wrong_request_auth_type_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
           #{ {update_headers_with, final} =>
                update_header_fun(<<"authorization">>, <<"Basic blahblah">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"invalid_auth_type">>}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

malformed_request_auth_not_params_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
           #{ {update_headers_with, final} =>
                update_header_fun(<<"authorization">>, <<"Signature blahblah;=;=;">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"invalid_header_params">>}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

malformed_request_auth_badly_quoted_params_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
           #{ {update_headers_with, final} =>
                update_header_fun(<<"authorization">>, <<"Signature blah=">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"invalid_header_params">>}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

missing_request_auth_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, final} => remove_header_fun(<<"authorization">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"missing_authorization_header">>}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

missing_request_digest_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, final} => remove_header_fun(<<"digest">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"{missing_header,<<\"digest\">>}">>}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

missing_request_request_id_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, final} => remove_header_fun(<<"x-request-id">>) } },
    ?assertMatch(
       {error, {{response_authentication, missing_request_id},
                {unauthorized, _Headers, <<"{missing_header,<<\"x-request-id\">>}">>}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

invalid_path_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => append_to_binary_fun(<<"/blah">>) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

negative_url_arity_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"-1">>, -1) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

big_url_arity_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"256">>, -1) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _body}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

nonnumeric_url_arity_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_url_with => replace_url_part_fun(<<"foobar">>, -1) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

unallowed_method_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_method_with => value_fun1(<<"GET">>) } },
    ?assertMatch(
       {error, {remote, {method_not_allowed, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

unauthorized_module_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {remote, {forbidden, _Headers, _Body}}},
       backwater:call(Endpoint, erlangsssss, '-', [Arg], Options)).

non_existing_module_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {remote, {not_found, _Headers, _Body}}},
       backwater:call(Endpoint, non_existing_module, '-', [Arg], Options)).

non_existing_function_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    ?assertMatch(
       {error, {remote, {not_found, _Headers, _Body}}},
       backwater:call(Endpoint, erlang, '-----', [Arg], Options)).

unsupported_content_type_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, before_compression} =>
                    update_header_fun(<<"content-type">>, <<"text/plain">>) } },
    ?assertMatch(
       {error, {remote, {unsupported_media_type, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

unsupported_content_encoding_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, before_authentication} =>
                    update_header_fun(<<"content-encoding">>, <<"deflate">>) } },
    ?assertMatch(
       {error, {remote, {unsupported_media_type, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

unsupported_accepted_content_encoding_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_headers_with, before_compression} =>
                    update_header_fun(<<"accept">>, <<"text/plain">>) } },
    ?assertMatch(
       {error, {remote, {not_acceptable, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

malformed_arguments_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_body_with, before_compression} =>
                    value_fun1(crypto:strong_rand_bytes(100)) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

malformed_compressed_arguments_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = ?STRING_COPIES_FOOBAR_1000,
    Override =
        #{ request =>
            #{ {update_body_with, before_authentication} =>
                    value_fun1(crypto:strong_rand_bytes(100)) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, length, [Arg], Options, Override)).

maliciously_compressed_arguments_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    % try to work around request and response limits by compressing when encoding
    EncodedArguments = term_to_binary([?ZEROES_PAYLOAD_50MiB], [compressed]),
    Override =
        #{ request =>
            #{ {update_body_with, before_compression} => value_fun1(EncodedArguments) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, length, [dummy], Options, Override)).

inconsistent_arguments_arity_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ update_arity_with => value_fun1(2) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [Arg], Options, Override)).

wrong_arguments_type_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    EncodedArguments = term_to_binary({}), % tuple instead of list
    Override =
        #{ request =>
            #{ {update_body_with,before_compression} => value_fun1(EncodedArguments) } },
    ?assertMatch(
       {error, {remote, {bad_request, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [dummy], Options, Override)).

wrong_arguments_digest_grouptest(Config) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    DummyArg = rand:uniform(1000),
    Override =
        #{ request =>
            #{ {update_body_with, final} =>
                    fun (RealBody) ->
                            crypto:strong_rand_bytes( byte_size(RealBody) )
                    end} },
    ?assertMatch(
       {error, {remote, {unauthorized, _Headers, _Body}}},
       backwater:'_call'(Endpoint, erlang, '-', [DummyArg], Options, Override)).

too_big_arguments_grouptest(Config) ->
    too_big_compressed_arguments_grouptest(Config, 9).

too_big_arguments_grouptest(Config, RetriesLeft) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    DummyArg = rand:uniform(1000),
    EncodedArguments = ?ZEROES_PAYLOAD_50MiB,
    Override =
        #{ request =>
            #{ {update_body_with, before_authentication} => value_fun1(EncodedArguments) } },

    case backwater:'_call'(Endpoint, erlang, '-', [DummyArg], Options, Override) of
        {error, {remote, {payload_too_large, _Headers, _Body}}} ->
            ok;
        {error, {hackney, closed}} when RetriesLeft > 0 ->
            % annoying concurrency issue
            too_big_arguments_grouptest(Config, RetriesLeft - 1)
    end.

too_big_compressed_arguments_grouptest(Config) ->
    too_big_compressed_arguments_grouptest(Config, 9).

too_big_compressed_arguments_grouptest(Config, RetriesLeft) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    DummyArg = rand:uniform(1000),
    EncodedArguments = ?ZEROES_PAYLOAD_50MiB,
    Override =
        #{ request =>
            #{ {update_body_with, before_compression} => value_fun1(EncodedArguments) } },

    case backwater:'_call'(Endpoint, erlang, '-', [DummyArg], Options, Override) of
        {error, {remote, {payload_too_large, _Headers, _Body}}} ->
            ok;
        {error, {hackney, closed}} when RetriesLeft > 0 ->
            % annoying concurrency issue
            too_big_compressed_arguments_grouptest(Config, RetriesLeft - 1)
    end.

exception_error_result_grouptest(Config) ->
    {name, Name} = lists:keyfind(name, 1, Config),
    {_Protocol, _DecodeUnsafeTerms, ReturnExceptionStacktraces} = decode_group_name(Name),
    exception_error_result_grouptest(Config, ReturnExceptionStacktraces).

exception_error_result_grouptest(Config, ReturnExceptionStacktraces) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
    Arg1 = rand:uniform(1000),
    Arg2 = 0,
    case ReturnExceptionStacktraces of
        true ->
            ?assertMatch(
               {error, {exception, {error, badarith, [{erlang,'/',[Arg1, Arg2], _}]}}},
               backwater:call(Endpoint, erlang, '/', [Arg1, Arg2], Options));
        false ->
            ?assertMatch(
               {error, {exception, {error, badarith, []}}},
               backwater:call(Endpoint, erlang, '/', [Arg1, Arg2], Options))
    end.

exception_throwing_result_grouptest(Config) ->
    {name, Name} = lists:keyfind(name, 1, Config),
    {_Protocol, _DecodeUnsafeTerms, ReturnExceptionStacktraces} = decode_group_name(Name),
    exception_throwing_result_grouptest(Config, ReturnExceptionStacktraces).

exception_throwing_result_grouptest(Config, ReturnExceptionStacktraces) ->
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, BaseOptions} = lists:keyfind(client_options, 1, Config),
    Options = BaseOptions#{ rethrow_remote_exceptions => true },
    Arg1 = rand:uniform(1000),
    Arg2 = 0,
    CaughtResult = (catch backwater:call(Endpoint, erlang, '/', [Arg1, Arg2], Options)),
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
    {name, Name} = lists:keyfind(name, 1, Config),
    {client_endpoint, Endpoint} = lists:keyfind(client_endpoint, 1, Config),
    {client_options, Options} = lists:keyfind(client_options, 1, Config),
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

    Result = backwater:'_call'(Endpoint, erlang, atom_to_binary, [placeholder, utf8],
                                      Options, Override),
    case DecodeUnsafeTerms of
        true ->
            ?assertEqual({ok, AtomName}, Result);
        false ->
            ?assertMatch({error, {remote, {bad_request, _Headers, _Body}}}, Result)
    end.

%%%
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
    TransportOpts = [{port, Port}],
    HackneyOpts = [],
    {Endpoint, start_clear_server, TransportOpts, HackneyOpts};
get_starting_params_(https) ->
    Port = ?TLS_PORT,
    Endpoint = <<"https://127.0.0.1:", (integer_to_binary(Port))/binary>>,
    TransportOpts =
        [{port, Port},
         {certfile, ssl_certificate_path()},
         {keyfile, ssl_key_path()}],
    HackneyOpts =
        [insecure,
         {ssl_options, [{server_name_indication, disable},
                        {verify, verify_none}]}],
    {Endpoint, start_tls_server, TransportOpts, HackneyOpts}.

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
