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
    rebar_api:debug("TransformedModuleInfo: ~p", [TransformedModuleInfo]),
    write_module(ClientRef, TransformedModuleInfo).

parse_module({attribute, _LineNumber, module, Module}, Acc) ->
    dict:store(module, Module, Acc);
parse_module({attribute, _LineNumber, export, Pairs}, Acc) ->
    dict:append_list(exports, Pairs, Acc);
parse_module({attribute, _LineNumber, export_type, Pairs}, Acc) ->
    dict:append_list(type_exports, Pairs, Acc);
parse_module({attribute, _LineNumber, backwater_module_version, RawVersion}, Acc) ->
    <<Version/binary>> = unicode:characters_to_binary(RawVersion),
    dict:store(backwater_module_version, Version, Acc);
parse_module({attribute, _LineNumber, backwater_export, {Name, Arity}}, Acc) ->
    dict:append(backwater_exports, {Name, Arity}, Acc);
parse_module({attribute, _LineNumber, backwater_exports, List}, Acc) when is_list(List) ->
    dict:append_list(backwater_exports, List, Acc);
parse_module({attribute, _LineNumber, record, {Name, FieldDefinitions}}, Acc) ->
    dict:append(record_definitions, {Name, FieldDefinitions}, Acc);
parse_module({attribute, _LineNumber, type, {Name, Definition, Args}}, Acc) ->
    Arity = length(Args),
    dict:append(type_specs, {{Name, Arity}, {Definition, Args}}, Acc);
parse_module({attribute, _LineNumber, spec, {{_Name, _Arity}, _Definitions} = Spec}, Acc) ->
    dict:append(function_specs, Spec, Acc);
parse_module({function, _LineNumber, Name, Arity, Clauses}, Acc) ->
    Definitions =
        lists:map(
          fun ({clause, _ClauseLineNumber, Vars, Guards, _Body}) when length(Vars) =:= Arity ->
                  #{ vars => Vars, guards => Guards }
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
           record_definitions => maps:new(),
           type_specs => maps:new(),
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
                  (record_definitions, RecordDefinitions) ->
                      maps:from_list(RecordDefinitions);
                  (type_specs, TypeSpecs) ->
                      maps:from_list(TypeSpecs);
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
    ModuleInfo4 = trim_type_specs(ModuleInfo3),
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

trim_type_specs(ModuleInfo1) ->
    ModuleInfo2 = externalize_function_specs_user_types(ModuleInfo1),
    ModuleInfo3 = externalize_type_specs_user_types(ModuleInfo2),
    ModuleInfo4 = determine_required_user_types(ModuleInfo3),
    #{ required_user_types := RequiredUserTypes,
       type_specs := TypeSpecs1 } = ModuleInfo4,
    TypeExports2 = sets:new(),
    TypeSpecs2 = maps:with(sets:to_list(RequiredUserTypes), TypeSpecs1),
    ModuleInfo4#{
      type_exports => TypeExports2,
      type_specs => TypeSpecs2 }.

rename_module(ModuleInfo) ->
    #{ module := Module1 } = ModuleInfo,
    Module2 = list_to_atom("backwater_" ++ atom_to_list(Module1)),
    ModuleInfo#{ module => Module2, original_module => Module1 }.

write_module(ClientRef, ModuleInfo) ->
    #{ dir := Dir, module := Module } = ModuleInfo,
    ModuleFilename = filename:join(Dir, atom_to_list(Module) ++ ".erl"),
    ModuleSrc = generate_module_source(ClientRef, ModuleInfo),
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

externalize_type_specs_user_types(ModuleInfo1) ->
    #{ type_specs := TypeSpecs1 } = ModuleInfo1,
    {TypeSpecs2, ModuleInfo2} =
        rebar3_backwater_util:maps_mapfold(
          fun externalize_type_spec_user_types/3,
          ModuleInfo1,
          TypeSpecs1),
    ModuleInfo2#{ type_specs => TypeSpecs2 }.

externalize_type_spec_user_types({_Name, _Arity}, {Definition1, Args1}, Acc1) ->
    {Definition2, Acc2} = externalize_user_types(Definition1, Acc1),
    {Args2, Acc3} = lists:mapfoldl(fun externalize_user_types/2, Acc2, Args1),
    {{Definition2, Args2}, Acc3}.

externalize_user_types({type, LineNumber, 'fun', [ArgSpecs1, ReturnSpec1]}, Acc1) ->
    {ArgSpecs2, Acc2} = externalize_user_types(ArgSpecs1, Acc1),
    {ReturnSpec2, Acc3} = externalize_user_types(ReturnSpec1, Acc2),
    {{type, LineNumber, 'fun', [ArgSpecs2, ReturnSpec2]}, Acc3};
externalize_user_types({type, LineNumber, bounded_fun, [FunSpec1, Constraints1]}, Acc1) ->
    {FunSpec2, Acc2} = externalize_user_types(FunSpec1, Acc1),
    {Constraints2, Acc3} = lists:mapfoldl(fun externalize_user_types/2, Acc2, Constraints1),
    {{type, LineNumber, bounded_fun, [FunSpec2, Constraints2]}, Acc3};
externalize_user_types({type, LineNumber, constraint, [ConstraintSpec1, ConstraintArgs1]}, Acc1) ->
    {ConstraintSpec2, Acc2} = externalize_user_types(ConstraintSpec1, Acc1),
    {ConstraintArgs2, Acc3} = lists:mapfoldl(fun externalize_user_types/2, Acc2, ConstraintArgs1),
    {{type, LineNumber, constraint, [ConstraintSpec2, ConstraintArgs2]}, Acc3};
externalize_user_types({remote_type, LineNumber, [ModuleSpec1, FunctionSpec1, Args1]}, Acc1) ->
    {ModuleSpec2, Acc2} = externalize_user_types(ModuleSpec1, Acc1),
    {FunctionSpec2, Acc3} = externalize_user_types(FunctionSpec1, Acc2),
    {Args2, Acc4} = lists:mapfoldl(fun externalize_user_types/2, Acc3, Args1),
    {{remote_type, LineNumber, [ModuleSpec2, FunctionSpec2, Args2]}, Acc4};
externalize_user_types({type, LineNumber, CompositeType, TypeSpecs1}, Acc1)
  when (CompositeType =:= list orelse
        CompositeType =:= map orelse
        CompositeType =:= map_field_assoc orelse
        CompositeType =:= map_field_exact orelse
        CompositeType =:= product orelse
        CompositeType =:= tuple orelse
        CompositeType =:= union),
       is_list(TypeSpecs1) ->
    {TypeSpecs2, Acc2} = lists:mapfoldl(fun externalize_user_types/2, Acc1, TypeSpecs1),
    {{type, LineNumber, CompositeType, TypeSpecs2}, Acc2};
externalize_user_types({user_type, LineNumber, Name, Params1}, Acc1) ->
    {Params2, Acc2} = lists:mapfoldl(fun externalize_user_types/2, Acc1, Params1),
    #{ module := Module, type_exports := TypeExports } = Acc2,
    Arity = length(Params2),
    Id = {Name, Arity},
    case sets:is_element(Id, TypeExports) of
        true ->
            {{remote_type, LineNumber, [{atom, LineNumber, Module}, {atom, LineNumber, Name}, Params2]},
             Acc2};
        false ->
            {{user_type, LineNumber, Name, Params2}, Acc2}
    end;
externalize_user_types(Decl, Acc) ->
    {Decl, Acc}.


determine_required_user_types(ModuleInfo1) ->
    #{ function_specs := FunctionSpecs } = ModuleInfo1,
    ModuleInfo2 =
        maps:fold(
          fun determine_required_user_types_in_function_spec/3,
          ModuleInfo1#{ required_user_types => sets:new() },
          FunctionSpecs),

    #{ record_definitions := RecordDefinitions } = ModuleInfo2,
    ModuleInfo3 =
        maps:fold(
          fun determine_required_user_types_in_record_definitions/3,
          ModuleInfo2,
          RecordDefinitions),
    ModuleInfo3.

determine_required_user_types_in_function_spec({_Name, _Arity}, Definitions, Acc) ->
    lists:foldl(fun determine_required_user_types/2, Acc, Definitions).

determine_required_user_types_in_record_definitions(_Name, FieldDefinitions, Acc) ->
    lists:foldl(fun determine_required_user_types/2, Acc, FieldDefinitions).

determine_required_user_types({type, _LineNumber, 'fun', [ArgSpecs, ReturnSpec]}, Acc1) ->
    Acc2 = determine_required_user_types(ArgSpecs, Acc1),
    determine_required_user_types(ReturnSpec, Acc2);
determine_required_user_types({type, _LineNumber, bounded_fun, [FunSpec, Constraints]}, Acc1) ->
    Acc2 = determine_required_user_types(FunSpec, Acc1),
    lists:foldl(fun determine_required_user_types/2, Acc2, Constraints);
determine_required_user_types({type, _LineNumber, constraint, [ConstraintSpec, ConstraintArgs]}, Acc1) ->
    Acc2 = determine_required_user_types(ConstraintSpec, Acc1),
    lists:foldl(fun determine_required_user_types/2, Acc2, ConstraintArgs);
determine_required_user_types({remote_type, _LineNumber, [ModuleSpec, FunctionSpec, Args]}, Acc1) ->
    Acc2 = determine_required_user_types(ModuleSpec, Acc1),
    Acc3 = determine_required_user_types(FunctionSpec, Acc2),
    lists:foldl(fun determine_required_user_types/2, Acc3, Args);
determine_required_user_types({type, _LineNumber, CompositeType, TypeSpecs}, Acc)
  when (CompositeType =:= list orelse
        CompositeType =:= map orelse
        CompositeType =:= map_field_assoc orelse
        CompositeType =:= map_field_exact orelse
        CompositeType =:= product orelse
        CompositeType =:= tuple orelse
        CompositeType =:= union),
       is_list(TypeSpecs) ->
    lists:foldl(fun determine_required_user_types/2, Acc, TypeSpecs);
determine_required_user_types({user_type, _LineNumber, Name, Params}, Acc1) ->
    Acc2 = lists:foldl(fun determine_required_user_types/2, Acc1, Params),
    Arity = length(Params),
    Id = {Name, Arity},
    #{ required_user_types := RequiredUserTypes1 } = Acc2,
    case sets:is_element(Id, RequiredUserTypes1) of
        true ->
            % loop detected, stop now
            rebar_api:debug("loop detected! ~p", [Id]),
            Acc1;
        false ->
            #{ type_specs := TypeSpecs } = Acc2,
            {ok, {Definition, Args}} = maps:find(Id, TypeSpecs),
            RequiredUserTypes2 = sets:add_element(Id, RequiredUserTypes1),
            Acc3 = Acc2#{ required_user_types => RequiredUserTypes2 },
            Acc4 = determine_required_user_types(Definition, Acc3),
            lists:foldl(fun determine_required_user_types/2, Acc4, Args)
    end;
determine_required_user_types(Decl, Acc) ->
    rebar_api:debug("ignoring: ~p", [Decl]),
    Acc.

generate_module_source(ClientRef, ModuleInfo) ->
    Header = generate_module_source_header(ModuleInfo),
    Exports = generate_module_source_exports(ModuleInfo),
    Types = generate_module_source_types(ModuleInfo),
    FunctionSpecs = generate_module_source_function_specs(ModuleInfo),
    FunctionDefinitions = generate_module_source_function_definitions(ClientRef, ModuleInfo),
    AllForms =
        (Header ++
         generate_module_source_section_header_comment("API Function Exports") ++
         Exports ++
         generate_module_source_section_header_comment("Type Definitions") ++
         Types ++
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
    rebar_api:debug("Exports: ~p", [Exports]),
    ExportsList = lists:sort( sets:to_list(Exports) ),
    [{attribute, 0, export, ExportsList}].

generate_module_source_types(ModuleInfo) ->
    #{ type_specs := TypeSpecs } = ModuleInfo,
    TypeSpecsList = lists:keysort(1, maps:to_list(TypeSpecs)),
    lists:map(
      fun ({{Name, _Arity}, {Definition, Args}}) ->
              {attribute, 0, type, {Name, Definition, Args}}
      end,
      TypeSpecsList).

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
            {attribute, ?DUMMY_LINE_NUMBER, spec, {{Name, Arity}, Definition}}
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

wrap_function_spec_return_types({type, LineNumber, 'fun', [ArgSpecs, ReturnSpec]}) ->
    WrappedReturnSpec = wrap_return_type(ReturnSpec),
    {type, LineNumber, 'fun', [ArgSpecs, WrappedReturnSpec]};
wrap_function_spec_return_types({type, LineNumber, bounded_fun, [FunSpec, Constraints]}) ->
    WrappedFunSpec = wrap_function_spec_return_types(FunSpec),
    {type, LineNumber, bounded_fun, [WrappedFunSpec, Constraints]}.

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
    Clauses =
        lists:map(
          fun (#{ vars := Vars, guards := Guards }) ->
                  Body = generate_module_source_function_body(ClientRef, OriginalModule, Name, Vars),
                  {clause, 0, Vars, Guards, Body}
          end,
          Definitions),
    {function, ?DUMMY_LINE_NUMBER, Name, Arity, Clauses}.

generate_module_source_function_body(ClientRef, OriginalModule, Name, Vars) ->
    [fully_qualified_call_clause(ClientRef, OriginalModule, Name, Vars)].

fully_qualified_call_clause(ClientRef, Module, Name, Vars) ->
    Call = {remote, ?DUMMY_LINE_NUMBER,
            {atom, ?DUMMY_LINE_NUMBER, backwater_client},
            {atom, ?DUMMY_LINE_NUMBER, call}},
    Args =
        [erl_syntax:abstract(ClientRef),
         {atom, ?DUMMY_LINE_NUMBER, Module}, {atom, ?DUMMY_LINE_NUMBER, Name},
         fully_qualified_call_clause_args(Vars)],
    {call, ?DUMMY_LINE_NUMBER, Call, Args}.

fully_qualified_call_clause_args([]) ->
    {nil, ?DUMMY_LINE_NUMBER};
fully_qualified_call_clause_args([H|T]) ->
    {cons, ?DUMMY_LINE_NUMBER, H, fully_qualified_call_clause_args(T)}.

generate_module_source_section_header_comment(Comment) ->
    Rule = "% ------------------------------------------------------------------",
    [erl_syntax:comment([Rule, "% " ++ Comment, Rule])].
