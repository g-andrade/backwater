-module(rebar3_plugin_SUITE).
-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

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

basic_rpc_test(_Config) ->
    generate_and_load(
      basic_rpc_test,
      [{crypto, crypto, [{exports, [{version,0}]}]}]),

    ?assertEqual(
       {ok, crypto:version()},
       rpc_crypto:version()).

%%%

generate_and_load(Ref, Targets) ->
    % code
    Opts =
        [{backwater_gen,
          [{client_ref, Ref},
           {output_directory, source_directory()}
           | [{target, Target} || Target <- Targets]]
         }],
    generate_and_load_code_with_opts(Opts),

    % client
    Secret = crypto:strong_rand_bytes(32),
    ok = backwater_client:start(Ref, #{ endpoint => <<"http://localhost:8080">>, secret => Secret }),

    % server
    ExposedModules =
        lists:map(
          fun ({_Application, Module, TargetOpts}) ->
                  {Module, lists_keywith([exports], 1, TargetOpts)}
          end,
          Targets),

    {ok, _Pid} = backwater_server:start_clear(
                   Ref, #{ secret => Secret, exposed_modules => ExposedModules },
                   [{port, 8080}], #{}).

generate_and_load_code_with_opts(OptsList) ->
    ok = file:set_cwd(source_directory()),
    RebarState1 = rebar_state:new(),
    {ok, RebarAppInfo1} = rebar_app_info:new(basic_rpc_test, "0.0.0", source_directory()),
    Opts = dict:from_list(OptsList),
    RebarAppInfo2 = rebar_app_info:opts(RebarAppInfo1, Opts),
    RebarState2 = rebar_state:current_app(RebarState1, RebarAppInfo2),
    {ok, RebarState3} = backwater_rebar3_prv_generate:init(RebarState2),
    {ok, _RebarState4} = backwater_rebar3_prv_generate:do(RebarState3),

    {backwater_gen, BackwaterOpts} = lists:keyfind(backwater_gen, 1, OptsList),
    TargetModules = [Module || {target, {_App, Module, _TargetOpts}} <- BackwaterOpts],
    lists:foreach(
      fun (TargetModule) ->
              TargetModuleStr = atom_to_list(TargetModule),
              ModuleStr = "rpc_" ++ TargetModuleStr,
              ModuleFilename = ModuleStr ++ ".erl",
              Module = list_to_atom(ModuleStr),
              %_ = file:delete(filename:join(source_directory(), ModuleFilename)),
              %_ = file:delete(filename:join(source_directory(), ModuleStr ++ ".beam")),
              {ok, Module} = compile:file(filename:join(source_directory(), ModuleFilename)),
              {module, Module} = code:load_abs(filename:join(source_directory(), ModuleStr))
      end,
      TargetModules).

all_individual_tests() ->
    [Name || {Name, 1} <- exported_functions(),
             lists:suffix("_test", atom_to_list(Name))].

exported_functions() ->
    ModuleInfo = ?MODULE:module_info(),
    {exports, Exports} = lists:keyfind(exports, 1, ModuleInfo),
    Exports.

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
