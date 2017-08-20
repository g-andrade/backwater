-module(rebar3_plugin_SUITE).
-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

-define(assertOk(Result), ?assertEqual(Result, ok)).

all() ->
    [{group, GroupName} || {GroupName, _Options, _TestCases} <- groups()].

groups() ->
    [{individual_tests, [sequence, shuffle], all_individual_tests()}].

init_per_group(_Name, Config) ->
    {ok, _} = application:ensure_all_started(backwater),
    Config.

end_per_group(_Name, Config) ->
    _ = application:stop(backwater),
    Config.

%%%

single_module_function_test(_Config) ->
    ?assertOk(
       with_ref(
         [{crypto, crypto, [{exports, [{version,0}]}]}],
         fun () ->
                 ?assertEqual(
                    [{version, 0}],
                    exported_functions(rpc_crypto)),

                 ?assertEqual(
                    {ok, crypto:version()},
                    rpc_crypto:version())
         end,
         [])).

whole_module_test(_Config) ->
    ?assertOk(
       with_ref(
         [{stdlib, math, [{exports, all}]}],
         fun () ->
                 ExportedFunctions = exported_functions(math),
                 ?assertEqual(
                    ExportedFunctions,
                    exported_functions(rpc_math)),

                 lists:foreach(
                   fun ({Function, Arity}) ->
                           Args = [rand:uniform() || _ <- lists:seq(1, Arity)],
                           compare_original_and_rpc_calls(math, rpc_math, Function, Args)
                   end,
                   ExportedFunctions)
         end,
         [])).

whole_module_presuming_attributes_test(_Config) ->
    ?assertOk(
       with_ref(
         [{stdlib, math}],
         fun () ->
                 % no attributes, so no functions are to be exported
                 ?assertEqual(
                    [],
                    exported_functions(rpc_math))
         end,
         [])).

current_app_module_test(_Config) ->
    ?assertOk(
       with_ref(
         [{backwater_util, [{exports, all}]}],
         fun () ->
                 ExportedFunctions = exported_functions(backwater_util),
                 ?assertEqual(
                    ExportedFunctions,
                    exported_functions(rpc_backwater_util)),

                 ?assertEqual(
                    {ok, backwater_util:latin1_binary_to_lower(<<"Hello">>)},
                    rpc_backwater_util:latin1_binary_to_lower(<<"Hello">>))
         end,
         [{output_src_dir, filename:join(source_directory(), "..")}])).

current_app_module_presuming_attributes_test(_Config) ->
    ?assertOk(
       with_ref(
         [backwater_util],
         fun () ->
                 % no attributes, so no functions are to be exported
                 ?assertEqual(
                    [],
                    exported_functions(rpc_backwater_util))
         end,
         [{output_src_dir, filename:join(source_directory(), "..")}])).

unloaded_application_test(_Config) ->
    ?assertOk(
       with_ref(
         [{eldap, eldap, [{exports, all}]}],
         fun () ->
                 ExportedFunctions = exported_functions(eldap),
                 ?assertEqual(
                    ExportedFunctions,
                    exported_functions(rpc_eldap)),

                 ?assertEqual(
                    {ok, eldap:substrings("cn", [{any,"V"}])},
                    rpc_eldap:substrings("cn", [{any,"V"}]))
         end,
         [])).

missing_application_test(_Config) ->
    ?assertMatch(
       {error, {backwater_rebar3_prv_generate, {unable_to_load_application, _}}},
       with_ref(
         [{some_made_up, application}],
         fun () -> error(not_supposed_to_run) end,
         [])).

missing_module_test(_Config) ->
    ?assertMatch(
       {error, {backwater_rebar3_prv_generate, {beam_lib, {file_error, _, enoent}}}},
       with_ref(
         [{stdlib, some_made_up_module}],
         fun () -> error(not_supposed_to_run) end,
         [])).

module_packed_in_escript_test(_Config) ->
    ?assertMatch(
       {error, {backwater_rebar3_prv_generate, {beam_lib, {file_error, _ModulePath, enotdir}}}},
       with_ref(
         [{rebar, rebar_app_info}],
         fun () -> error(not_supposed_to_run) end,
         [])).

module_with_backwater_attributes_test(_Config) ->
    ?assertOk(
       with_ref(
         [module_with_backwater_attributes],
         fun () ->
                 ?assertEqual(
                    [{exported_functionA,0},
                     {exported_functionC,0},
                     {exported_functionD,1}],
                    exported_functions(rpc_module_with_backwater_attributes)),

                 ?assertEqual(
                    {ok, {foobar}},
                    rpc_module_with_backwater_attributes:exported_functionA()),

                 ?assertEqual(
                    {ok, {barfoo}},
                    rpc_module_with_backwater_attributes:exported_functionC()),

                 ArgD = rand:uniform(1 bsl 32),
                 ?assertEqual(
                    {ok, {ArgD}},
                    rpc_module_with_backwater_attributes:exported_functionD(ArgD))
         end,
         [{src_dirs, [source_directory()]}])).

%%%

compare_original_and_rpc_calls(Module, RpcModule, Function, Args) ->
    Arity = length(Args),
    ct:pal("comparing ~p vs ~p", [{Module,Function,Arity}, {RpcModule,Function,Arity}]),
    ExpectedResult =
        try
            Success = apply(Module, Function, Args),
            ct:pal("success result: ~p", [Success]),
            {ok, Success}
        catch
            Class:Exception ->
                Stacktrace = erlang:get_stacktrace(),
                PurgedStacktrace =
                    backwater_util:purge_stacktrace_below(
                      {?MODULE,compare_original_and_rpc_calls,4},
                      Stacktrace),
                ct:pal("exception result: ~p", [{Class, Exception, PurgedStacktrace}]),
                {error, {exception, {Class, Exception, PurgedStacktrace}}}
        end,
    ?assertEqual(
       ExpectedResult,
       apply(RpcModule, Function, Args)).

with_ref(Targets, Fun, ExtraOpts) ->
    Ref = rand:uniform(1 bsl 64),
    try
        backwater_util:with_success(
          Fun,
          generate_and_load(Ref, Targets, ExtraOpts))
    after
        stop(Ref)
    end.

generate_and_load(Ref, Targets, ExtraOpts) ->
    % client
    Secret = crypto:strong_rand_bytes(32),
    ok = backwater_client:start(Ref, #{ endpoint => <<"http://localhost:8080">>, secret => Secret }),

    % server
    ExposedModules =
        lists:map(
          fun ({_App, Module, TargetOpts}) ->
                  {Module, lists_keywith([exports], 1, TargetOpts)};
              ({App, Module}) when is_atom(App), is_atom(Module) ->
                  Module;
              ({Module, TargetOpts}) when is_atom(Module), is_list(TargetOpts) ->
                  {Module, TargetOpts};
              (Module) when is_atom(Module) ->
                  Module
          end,
          Targets),

    {ok, _Pid} = backwater_server:start_clear(
                   Ref, #{ secret => Secret, exposed_modules => ExposedModules,
                           return_exception_stacktraces => true },
                   [{port, 8080}], #{}),

    OutputDirectory = proplists:get_value(output_src_dir, ExtraOpts, source_directory()),
    SourceDirectories = proplists:get_value(src_dirs, ExtraOpts),
    % code
    Opts =
        [{backwater_gen,
          [{client_ref, Ref},
           {output_src_dir, OutputDirectory}
           | [{target, Target} || Target <- Targets]]
         },
         {src_dirs, SourceDirectories}],
    FilteredOpts = lists_keyfilter(fun is_defined/1, 2, Opts),
    generate_and_load_code_with_opts(FilteredOpts, OutputDirectory).


stop(Ref) ->
    ok = backwater_server:stop_listener(Ref),
    ok = backwater_client:stop(Ref).

generate_and_load_code_with_opts(OptsList, Outputdirectory) ->
    {backwater_gen, BackwaterOpts} = lists:keyfind(backwater_gen, 1, OptsList),
    Targets = [Target || {target, Target} <- BackwaterOpts],
    TargetModules =
        lists:map(
          fun ({_App, Module, _TargetOpts}) ->
                  Module;
              ({App, Module}) when is_atom(App), is_atom(Module) ->
                  Module;
              ({Module, TargetOpts}) when is_atom(Module), is_list(TargetOpts) ->
                  Module;
              (Module) when is_atom(Module) ->
                  Module
          end,
          Targets),

    lists:foreach(
      fun (TargetModule) ->
              TargetModuleStr = atom_to_list(TargetModule),
              ModuleStr = "rpc_" ++ TargetModuleStr,
              ModuleFilename = ModuleStr ++ ".erl",
              _ = file:delete(filename:join(Outputdirectory, ModuleFilename)),
              _ = file:delete(filename:join(Outputdirectory, ModuleStr ++ ".beam"))
      end,
      TargetModules),

    ok = file:set_cwd(Outputdirectory),
    RebarState1 = rebar_state:new(),
    {ok, RebarAppInfo1} = rebar_app_info:new(basic_rpc_test, "0.0.0", Outputdirectory),
    Opts = dict:from_list(OptsList),
    RebarAppInfo2 = rebar_app_info:opts(RebarAppInfo1, Opts),
    RebarState2 = rebar_state:current_app(RebarState1, RebarAppInfo2),
    {ok, RebarState3} = backwater_rebar3_prv_generate:init(RebarState2),
    backwater_util:with_success(
      fun (_RebarState4) ->
              lists:foreach(
                fun (TargetModule) ->
                        TargetModuleStr = atom_to_list(TargetModule),
                        ModuleStr = "rpc_" ++ TargetModuleStr,
                        ModuleFilename = ModuleStr ++ ".erl",
                        Module = list_to_atom(ModuleStr),
                        {ok, Module} = compile:file(filename:join(Outputdirectory, ModuleFilename)),
                        {module, Module} = code:load_abs(filename:join(Outputdirectory, ModuleStr))
                end,
                TargetModules)
      end,
      backwater_rebar3_prv_generate:do(RebarState3)).

all_individual_tests() ->
    [Name || {Name, 1} <- exported_functions(),
             lists:suffix("_test", atom_to_list(Name))].

exported_functions() ->
    exported_functions(?MODULE).

exported_functions(Module) ->
    ModuleInfo = Module:module_info(),
    {exports, AllExports} = lists:keyfind(exports, 1, ModuleInfo),
    AllSortedExports = ordsets:from_list(AllExports),
    SortedExclusions =
        [{module_info, 0},
         {module_info, 1}],
    SortedExports = ordsets:subtract(AllSortedExports, SortedExclusions),
    ordsets:to_list(SortedExports).

make_dir(Path) ->
    case file:make_dir(Path) of
        ok -> ok;
        {error, eexist} -> ok;
        {error, Error} -> {error, Error}
    end.

source_directory() ->
    % very dirty hack
    ModuleInfo = ?MODULE:module_info(),
    {compile, CompileOptions} = lists:keyfind(compile, 1, ModuleInfo),
    {source, Source} = lists:keyfind(source, 1, CompileOptions),
    filename:dirname(Source).

lists_keywith(Keys, N, List) ->
    lists_keyfilter(
      fun (Key) -> lists:member(Key, Keys) end,
      N, List).

lists_keyfilter(Fun, N, List) ->
    [Tuple || Tuple <- List, Fun(element(N, Tuple))].

is_defined(V) -> V =/= undefined.
