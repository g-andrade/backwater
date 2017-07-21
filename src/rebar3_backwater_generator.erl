-module(rebar3_backwater_generator).

-export([generate/1]).

-define(DUMMY_LINE_NUMBER, 1).

-spec generate(rebar_app_info:t()) -> ok.
generate(AppInfo) ->
    AppSourceFiles = app_source_files(AppInfo),

    Opts = rebar_app_info:opts(AppInfo),
    {ok, BackwaterOpts} = dict:find(backwater_opts, Opts),
    ClientRef = get_backwater_opt(client_ref, BackwaterOpts),

    lists:foreach(
      fun (AppSourceFile) ->
              lists:suffix("/test_exposed_module.erl", AppSourceFile) andalso
              generate_backwater_code(ClientRef, AppSourceFile)
      end,
      AppSourceFiles).

get_backwater_opt(Key, Opts) ->
    case lists:keyfind(Key, 1, Opts) of
        {Key, Value} -> Value;
        false -> error({missing_backwater_opt, Key})
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
app_source_files(AppInfo) ->
    AppDir = rebar_app_info:dir(AppInfo),
    case file:list_dir(AppDir) of
        {ok, Filenames} ->
            PossibleSrcDirs = filter_ci_filenames(Filenames, "src"),
            FullPossibleSrcDirs = full_paths(AppDir, PossibleSrcDirs),
            UnflattenedSourceFiles = [directory_source_files(SrcDir) || SrcDir <- FullPossibleSrcDirs],
            lists:foldl(fun erlang:'++'/2, [], UnflattenedSourceFiles);
        {error, OtherError} ->
            error({cant_list_directory, AppDir, OtherError})
    end.

directory_source_files(SrcDir) ->
    case file:list_dir(SrcDir) of
        {ok, Filenames} ->
            FilteredFilenames = filter_ci_filenames_by_extension(Filenames, "erl"),
            full_paths(SrcDir, FilteredFilenames);
        {error, enotdir} ->
            [];
        {error, OtherError} ->
            error({cant_list_directory, SrcDir, OtherError})
    end.

filter_ci_filenames(Filenames, Match) ->
    LowMatch = filename_to_lower(Match),
    lists:filter(
      fun (Filename) -> filename_to_lower(Filename) =:= LowMatch end,
      Filenames).

filter_ci_filenames_by_extension(Filenames, Extension) ->
    LowExtensionWithDot = "." ++ filename_to_lower(Extension),
    lists:filter(
      fun (Filename) ->
              LowFilename = filename_to_lower(Filename),
              (lists:suffix(LowExtensionWithDot, LowFilename) andalso
               length(LowFilename) > length(LowExtensionWithDot))
      end,
      Filenames).

full_paths(Dir, Names) ->
    [filename:join(Dir, Name) || Name <- Names].

filename_to_lower(Filename) ->
    % FIXME unistring no longer needed in OTP 20 (I think)
    unistring:to_lower(Filename).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
generate_backwater_code(ClientRef, ModuleFilename) ->
    AbsForm = forms:read(ModuleFilename),
    rebar_api:debug("AbsForm: ~p", [AbsForm]),
    ParseResult = lists:foldl(fun parse_module/2, dict:new(), AbsForm),
    rebar_api:debug("ParseResult: ~p", [dict:to_list(ParseResult)]),
    ModuleInfo = generate_module_info(ParseResult, ModuleFilename),
    rebar_api:debug("ModuleInfo: ~p", [maps:to_list(ModuleInfo)]),
    TransformedModuleInfo = (catch transform_module(ModuleInfo)),
    %rebar_api:debug("TransformedModuleInfo: ~p", [TransformedModuleInfo]),
    write_module(ClientRef, TransformedModuleInfo).

parse_module({attribute, _Line, module, Module}, Acc) ->
    dict:store(module, Module, Acc);
parse_module({attribute, _Line, export, Pairs}, Acc) ->
    dict:append_list(exports, Pairs, Acc);
parse_module({attribute, _Line, export_type, Pairs}, Acc) ->
    dict:append_list(type_exports, Pairs, Acc);
parse_module({attribute, _Line, backwater_module_version, RawVersion}, Acc) ->
    <<Version/binary>> = unicode:characters_to_binary(RawVersion),
    dict:store(backwater_module_version, Version, Acc);
parse_module({attribute, _Line, backwater_export, {Name, Arity}}, Acc) ->
    dict:append(backwater_exports, {Name, Arity}, Acc);
parse_module({attribute, _Line, backwater_exports, List}, Acc) when is_list(List) ->
    dict:append_list(backwater_exports, List, Acc);
parse_module({attribute, _Line, spec, {{_Name, _Arity}, _Definitions} = Spec}, Acc) ->
    dict:append(function_specs, Spec, Acc);
parse_module({function, _Line, Name, Arity, Clauses}, Acc) ->
    Definitions =
        lists:map(
          fun ({clause, _ClauseLine, Vars, _Guards, _Body}) when length(Vars) =:= Arity ->
                  #{ vars => Vars }
          end,
          Clauses),

    dict:update(
      function_definitions,
      fun (Previous) -> dict:append_list({Name, Arity}, Definitions, Previous) end,
      dict:from_list([{{Name, Arity}, Definitions}]),
      Acc);
parse_module(_Other, Acc) ->
    %rebar_api:debug("ignoring ~p", [Other]),
    Acc.

generate_module_info(ParseResult, ModuleFilename) ->
    BaseModuleInfo =
        #{ exports => sets:new(),
           type_exports => sets:new(),
           backwater_exports => sets:new(),
           function_specs => maps:new(),
           function_definitions => maps:new(),
           dir => filename:dirname(ModuleFilename) },

    ModuleInfo =
        maps:from_list(
          dict:to_list(
            dict:map(
              fun (module, Module) ->
                      Module;
                  (exports, Exports) ->
                      sets:from_list(Exports);
                  (type_exports, TypeExports) ->
                      sets:from_list(TypeExports);
                  (backwater_module_version, Version) ->
                      Version;
                  (backwater_exports, BackwaterExports) ->
                      sets:from_list(BackwaterExports);
                  (function_specs, FunctionSpecs) ->
                      maps:from_list(FunctionSpecs);
                  (function_definitions, FunctionDefinitions) ->
                      maps:from_list( dict:to_list(FunctionDefinitions) )
              end,
              ParseResult))),

    maps:merge(BaseModuleInfo, ModuleInfo).

transform_module(ModuleInfo1) ->
    ModuleInfo2 = trim_exports(ModuleInfo1),
    ModuleInfo3 = trim_functions_and_specs(ModuleInfo2),
    ModuleInfo4 = externalize_function_specs_user_types(ModuleInfo3),
    rename_module(ModuleInfo4).

trim_exports(ModuleInfo) ->
    #{ exports := Exports, backwater_exports := BackwaterExports } = ModuleInfo,
    Intersection = sets:intersection(Exports, BackwaterExports),
    (maps:remove(backwater_exports, ModuleInfo))#{ exports => Intersection }.

trim_functions_and_specs(ModuleInfo) ->
    #{ exports := Exports,
       function_definitions := FunctionDefinitions,
       function_specs := FunctionSpecs } = ModuleInfo,
    ModuleInfo#{
      function_definitions => maps:with(sets:to_list(Exports), FunctionDefinitions),
      function_specs => maps:with(sets:to_list(Exports), FunctionSpecs) }.

rename_module(ModuleInfo) ->
    #{ module := Module1 } = ModuleInfo,
    Module2 = list_to_atom("backwater_" ++ atom_to_list(Module1)),
    ModuleInfo#{ module => Module2, original_module => Module1 }.

write_module(ClientRef, ModuleInfo) ->
    #{ dir := Dir, module := Module } = ModuleInfo,
    ModuleFilename = filename:join(Dir, atom_to_list(Module) ++ ".erl"),
    ModuleSrc = (catch generate_module_source(ClientRef, ModuleInfo)),
    rebar_api:debug("module src: ~p", [ModuleSrc]),
    case file:write_file(ModuleFilename, ModuleSrc) of
        ok -> ok;
        {error, Error} -> error({couldnt_save_module, Error})
    end.


externalize_function_specs_user_types(ModuleInfo1) ->
    #{ function_specs := FunctionSpecs1 } = ModuleInfo1,
    {FunctionSpecs2, ModuleInfo2} =
        rebar3_backwater_util:maps_mapfold(
          fun externalize_function_spec_definitions_user_types/3,
          ModuleInfo1,
          FunctionSpecs1),
    ModuleInfo2#{ function_specs => FunctionSpecs2 }.

externalize_function_spec_definitions_user_types({_Name, _Arity}, Definitions, Acc) ->
    lists:mapfoldl(fun externalize_user_types/2, Acc, Definitions).


externalize_user_types({type, Line, record, Args}, Acc1) ->
    rebar_api:debug("record ~p, replaced by generic term - use exported type instead", [Args]),
    {{type, Line, term, []}, Acc1};
externalize_user_types({user_type, Line, Name, Args1}, Acc1) ->
    {Args2, Acc2} = externalize_user_types(Args1, Acc1),
    #{ module := Module, type_exports := TypeExports } = Acc2,
    Arity = length(Args2),
    Id = {Name, Arity},
    sets:is_element(Id, TypeExports) orelse rebar_api:debug("type ~p/~p not exported", [Name, Arity]),
    {{remote_type, Line, [{atom, Line, Module}, {atom, Line, Name}, Args2]}, Acc2};
externalize_user_types(List, Acc) when is_list(List) ->
    lists:mapfoldl(fun externalize_user_types/2, Acc, List);
externalize_user_types(Literal, Acc) when is_atom(Literal); is_integer(Literal) ->
    {Literal, Acc};
externalize_user_types({LiteralType, _Line, _LiteralValue} = T, Acc)
  when LiteralType =:= atom;
       LiteralType =:= char;
       LiteralType =:= float;
       LiteralType =:= integer;
       LiteralType =:= string ->
    {T, Acc};
externalize_user_types({ann_type, Line, Types1}, Acc1) ->
    {Types2, Acc2} = externalize_user_types(Types1, Acc1),
    {{ann_type, Line, Types2}, Acc2};
externalize_user_types({op, Line, Op, Arg1}, Acc1) ->
    % unary operator
    {Arg2, Acc2} = externalize_user_types(Arg1, Acc1),
    {{op, Line, Op, Arg2}, Acc2};
externalize_user_types({op, Line, Op, Left1, Right1}, Acc1) ->
    % binary operator
    {Left2, Acc2} = externalize_user_types(Left1, Acc1),
    {Right2, Acc3} = externalize_user_types(Right1, Acc2),
    {{op, Line, Op, Left2, Right2}, Acc3};
externalize_user_types({remote_type, Line, [ModuleSpec1, FunctionSpec1, Args1]}, Acc1) ->
    {ModuleSpec2, Acc2} = externalize_user_types(ModuleSpec1, Acc1),
    {FunctionSpec2, Acc3} = externalize_user_types(FunctionSpec1, Acc2),
    {Args2, Acc4} = externalize_user_types(Args1, Acc3),
    {{remote_type, Line, [ModuleSpec2, FunctionSpec2, Args2]}, Acc4};
externalize_user_types({type, _Line, _Builtin, any} = T, Acc) ->
    {T, Acc};
externalize_user_types({type, Line, Builtin, Args1}, Acc1) when is_list(Args1) ->
    {Args2, Acc2} = externalize_user_types(Args1, Acc1),
    {{type, Line, Builtin, Args2}, Acc2};
externalize_user_types({var, _Line, _Name} = T, Acc) ->
    {T, Acc}.


generate_module_source(ClientRef, ModuleInfo) ->
    Header = generate_module_source_header(ModuleInfo),
    Exports = generate_module_source_exports(ModuleInfo),
    FunctionSpecs = generate_module_source_function_specs(ModuleInfo),
    FunctionDefinitions = generate_module_source_function_definitions(ClientRef, ModuleInfo),
    AllForms =
        (Header ++
         generate_module_source_section_header_comment("API Function Exports") ++
         Exports ++
         generate_module_source_section_header_comment("API Function Specifications") ++
         FunctionSpecs ++
         generate_module_source_section_header_comment("API Function Definitions") ++
         FunctionDefinitions),

    SyntaxTree = erl_syntax:form_list(AllForms),
    PrettyHookF =
        fun(Node, Ctxt, Cont) ->
                Doc = Cont(Node, Ctxt),
                prettypr:above(prettypr:empty(), Doc)
        end,
    erl_prettypr:format(SyntaxTree, [{hook, PrettyHookF}, {paper, 160}, {ribbon, 120}]).

generate_module_source_header(ModuleInfo) ->
    #{ module := Module } = ModuleInfo,
    [{attribute, 0, module, Module}].

generate_module_source_exports(ModuleInfo) ->
    #{ exports := Exports } = ModuleInfo,
    %rebar_api:debug("Exports: ~p", [Exports]),
    ExportsList = lists:sort( sets:to_list(Exports) ),
    [{attribute, 0, export, ExportsList}].

generate_module_source_function_specs(ModuleInfo) ->
    #{ function_definitions := FunctionDefinitions } = ModuleInfo,
    FunctionNameArities = lists:keysort(1, maps:keys(FunctionDefinitions)),
    lists:map(
      fun ({Name, Arity}) ->
              generate_module_source_function_spec({Name, Arity}, ModuleInfo)
      end,
      FunctionNameArities).

generate_module_source_function_spec({Name, Arity}, ModuleInfo) ->
    #{ function_specs := FunctionSpecs } = ModuleInfo,
    case maps:find({Name, Arity}, FunctionSpecs) of
        {ok, Definitions} ->
            WrappedDefinitions =
                [wrap_function_spec_return_types(Definition) || Definition <- Definitions],
            {attribute, ?DUMMY_LINE_NUMBER, spec, {{Name, Arity}, WrappedDefinitions}};
        error ->
            Definition = generic_function_spec(Arity),
            {attribute, ?DUMMY_LINE_NUMBER, spec, {{Name, Arity}, [Definition]}}
    end.

generate_module_source_function_definitions(ClientRef, ModuleInfo) ->
    #{ function_definitions := FunctionDefinitions,
       original_module := OriginalModule } = ModuleInfo,
    FunctionDefinitionsList = lists:keysort(1, maps:to_list(FunctionDefinitions)),
    lists:map(
      fun (FunctionDefinitionKV) ->
              generate_module_source_function(ClientRef, FunctionDefinitionKV, OriginalModule)
      end,
      FunctionDefinitionsList).

wrap_function_spec_return_types({type, Line, 'fun', [ArgSpecs, ReturnSpec]}) ->
    WrappedReturnSpec = wrap_return_type(ReturnSpec),
    {type, Line, 'fun', [ArgSpecs, WrappedReturnSpec]};
wrap_function_spec_return_types({type, Line, bounded_fun, [FunSpec, Constraints]}) ->
    WrappedFunSpec = wrap_function_spec_return_types(FunSpec),
    {type, Line, bounded_fun, [WrappedFunSpec, Constraints]}.

generic_function_spec(Arity) ->
    TermType = {type, ?DUMMY_LINE_NUMBER, term, []},
    ArgSpecs = {type, ?DUMMY_LINE_NUMBER, product, rebar3_backwater_util:copies(TermType, Arity)},
    ReturnSpec = wrap_return_type(TermType),
    {type, ?DUMMY_LINE_NUMBER, 'fun', [ArgSpecs, ReturnSpec]}.

wrap_return_type(OriginalType) ->
    SuccessSpec =
        {type, ?DUMMY_LINE_NUMBER, tuple,
         [{atom, ?DUMMY_LINE_NUMBER, ok}, OriginalType]},
    ErrorValueSpec =
        {remote_type, ?DUMMY_LINE_NUMBER,
         [{atom, ?DUMMY_LINE_NUMBER, backwater_client},
          {atom, ?DUMMY_LINE_NUMBER, error},
          []]},
    ErrorSpec =
        {type, ?DUMMY_LINE_NUMBER, tuple,
         [{atom, ?DUMMY_LINE_NUMBER, error}, ErrorValueSpec]},
    {type, ?DUMMY_LINE_NUMBER, union, [SuccessSpec, ErrorSpec]}.

generate_module_source_function(ClientRef, {{Name, Arity}, Definitions}, OriginalModule) ->
    IndexedVarLists = generate_module_source_indexed_var_lists(Definitions),
    ArgNames = generate_module_source_arg_names(IndexedVarLists),
    UniqueArgNames = generate_module_source_unique_arg_names(ArgNames),
    ArgVars = [{var, ?DUMMY_LINE_NUMBER, list_to_atom(StringName)} || StringName <- UniqueArgNames],
    Guards = [],
    Body = generate_module_source_function_body(ClientRef, OriginalModule, Name, ArgVars),
    Clause = {clause, ?DUMMY_LINE_NUMBER, ArgVars, Guards, Body},
    {function, ?DUMMY_LINE_NUMBER, Name, Arity, [Clause]}.

generate_module_source_indexed_var_lists(Definitions) ->
    IndexedVarListsDict =
        lists:foldl(
          fun (#{ vars := Vars }, AccA) ->
                  EnumeratedVars = rebar3_backwater_util:lists_enumerate(Vars),
                  lists:foldl(
                    fun ({Index, Var}, AccB) ->
                            orddict:append(Index, Var, AccB)
                    end,
                    AccA,
                    EnumeratedVars)
          end,
          orddict:new(),
          Definitions),
    orddict:to_list(IndexedVarListsDict).

generate_module_source_arg_names(IndexedVarLists) ->
    lists:map(
      fun ({Index, Vars}) ->
              ArgNames = filter_arg_names_from_function_vars(Vars),
              CleanArgNames = lists:map(fun clean_arg_name/1, ArgNames),
              ValidArgNames = lists:filter(fun is_valid_arg_name/1, CleanArgNames),
              UniqueArgNames1 = lists:usort(ValidArgNames),
              UniqueArgNames2 =
                case UniqueArgNames1 =:= [] of
                    true -> [generated_arg_name(Index)];
                    false -> UniqueArgNames1
                end,
              string:join(UniqueArgNames2, "_Or_")
      end,
      IndexedVarLists).

filter_arg_names_from_function_vars(Vars) ->
    lists:foldr(
      fun F({var, _Line, AtomName}, Acc) ->
              [atom_to_list(AtomName) | Acc];
          F({match, _Line1, Left, Right}, Acc1) ->
              Acc2 = F(Right, Acc1),
              F(Left, Acc2);
          F(Other, Acc) ->
              rebar_api:debug("filtering out arg names from function vars: ~p", [Other]),
              Acc
      end,
      [],
      Vars).

clean_arg_name(ArgName1) ->
    ArgName2 = lists:dropwhile(fun (C) -> C =:= $_ end, ArgName1), % drop prefixing underscores
    lists:takewhile(fun (C) -> C =/= $_ end, ArgName2).            % drop trailing underscores

is_valid_arg_name(ArgName) ->
    length(ArgName) > 0 andalso                        % non-empty
    [hd(ArgName)] =:= string:to_upper([hd(ArgName)]).  % first character is upper case

generated_arg_name(Index) ->
    "Arg" ++ integer_to_list(Index).

generate_module_source_unique_arg_names(ArgNames) ->
    CountPerArgName =
        lists:foldl(
          fun (ArgName, Acc) ->
                  dict:update_counter(ArgName, +1, Acc)
          end,
          dict:new(),
          ArgNames),

    case lists:any(fun ({_ArgName, Count}) -> Count > 1 end, dict:to_list(CountPerArgName)) of
        false ->
            % no conflicts
            ArgNames;
        true ->
            {MappedArgNames, _} =
                lists:mapfoldl(
                  fun (ArgName, Index) ->
                          MappedArgName =
                            case dict:fetch(ArgName, CountPerArgName) of
                                1 -> ArgName;
                                _ -> generated_arg_name(Index)
                            end,
                          {MappedArgName, Index + 1}
                  end,
                  1,
                  ArgNames),

            generate_module_source_unique_arg_names(MappedArgNames)
    end.

generate_module_source_function_body(ClientRef, OriginalModule, Name, ArgVars) ->
    [fully_qualified_call_clause(ClientRef, OriginalModule, Name, ArgVars)].

fully_qualified_call_clause(ClientRef, Module, Name, ArgVars) ->
    Call = {remote, ?DUMMY_LINE_NUMBER,
            {atom, ?DUMMY_LINE_NUMBER, backwater_client},
            {atom, ?DUMMY_LINE_NUMBER, call}},
    Args =
        [erl_syntax:abstract(ClientRef),
         {atom, ?DUMMY_LINE_NUMBER, Module}, {atom, ?DUMMY_LINE_NUMBER, Name},
         fully_qualified_call_clause_args(ArgVars)],
    {call, ?DUMMY_LINE_NUMBER, Call, Args}.

fully_qualified_call_clause_args([]) ->
    {nil, ?DUMMY_LINE_NUMBER};
fully_qualified_call_clause_args([H|T]) ->
    {cons, ?DUMMY_LINE_NUMBER, H, fully_qualified_call_clause_args(T)}.

generate_module_source_section_header_comment(Comment) ->
    Rule = "% ------------------------------------------------------------------",
    [erl_syntax:comment([Rule, "% " ++ Comment, Rule])].
