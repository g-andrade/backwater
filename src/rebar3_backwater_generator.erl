-module(rebar3_backwater_generator).

-export([generate/1]).

-define(DEFAULT_PARAM_CLIENT_REF, default).
-define(DEFAULT_PARAM_EXPORTS, use_backwater_attributes).
-define(DEFAULT_PARAM_UNEXPORTED_TYPES, warn).
-define(DEFAULT_BACKWATER_MODULE_VERSION, "1").
-define(DUMMY_LINE_NUMBER, 1).

-spec generate(State :: rebar_state:t()) -> ok.
generate(State) ->
    AppInfos =
        case rebar_state:current_app(State) of
            undefined ->
                rebar_state:project_apps(State);
            AppInfo ->
                [AppInfo]
        end,

    SourceDirectoriesPerApp =
        lists:foldl(
          fun (AppInfo, Acc) ->
                  AppName = binary_to_atom(rebar_app_info:name(AppInfo), utf8),
                  AppSourceDirectories = app_info_src_directories(AppInfo),
                  dict:append_list(AppName, AppSourceDirectories, Acc)
          end,
          dict:new(),
          AppInfos ++ rebar_state:all_deps(State)),

    lists:map(
      fun (AppInfo) ->
              generate(AppInfo, SourceDirectoriesPerApp)
      end,
      AppInfos).

generate(CurrentAppInfo, SourceDirectoriesPerApp) ->
    RebarOpts = rebar_app_info:opts(CurrentAppInfo),
    {ok, BackwaterOpts} = dict:find(backwater_opts, RebarOpts), % TODO don't crash when missing?
    UnprocessedTargets = proplists:get_all_values(target, BackwaterOpts),
    CurrentAppName = binary_to_atom(rebar_app_info:name(CurrentAppInfo), utf8),

    GlobalTargetOpts =
        lists:filter(
          fun ({target, _}) -> false;
              (_) -> true
          end,
          BackwaterOpts),

    Targets =
        lists:map(
          fun (Module) when is_atom(Module) ->
                  {CurrentAppName, Module, GlobalTargetOpts};
              ({Module, Opts}) when is_atom(Module), is_list(Opts) ->
                  MergedOpts = rebar3_backwater_util:proplists_sort_and_merge(GlobalTargetOpts, Opts),
                  {CurrentAppName, Module, MergedOpts};
              ({AppName, Module}) when is_atom(AppName), is_atom(Module) ->
                  {AppName, Module, GlobalTargetOpts};
              ({AppName, Module, Opts}) when is_atom(AppName), is_atom(Module), is_list(Opts) ->
                  MergedOpts = rebar3_backwater_util:proplists_sort_and_merge(GlobalTargetOpts, Opts),
                  {AppName, Module, MergedOpts}
          end,
          UnprocessedTargets),

    lists:foreach(
      fun ({AppName, Module, TargetOpts}) ->
              {ok, GenerationParams1} = find_module_name_or_path(AppName, Module, SourceDirectoriesPerApp),
              GenerationParams2 =
                    GenerationParams1#{
                      current_app_info => CurrentAppInfo,
                      target_opts => TargetOpts },
              ok = generate_backwater_code(GenerationParams2)
      end,
      Targets).

app_info_src_directories(AppInfo) ->
    BaseDir = rebar_app_info:dir(AppInfo),
    Opts = rebar_app_info:opts(AppInfo),
    RelDirs = rebar_opts:get(Opts, src_dir, ["src"]),
    [filename:join(ec_cnv:to_list(BaseDir), RelDir) || RelDir <- RelDirs].

find_module_name_or_path(AppName, Module, SourceDirectoriesPerApp) ->
    case dict:find(AppName, SourceDirectoriesPerApp) of
        {ok, SourceDirectories} ->
            find_module_path(Module, SourceDirectories);
        error ->
            case application:load(AppName) of
                ok ->
                    {ok, #{ module_name => Module }};
                {error, {already_loaded, AppName}} ->
                    {ok, #{ module_name => Module }};
                {error, Error} ->
                    {error, {unable_to_load_application, Error}}
            end
    end.

find_module_path(Module, SourceDirectories) ->
    ModuleStr = atom_to_list(Module),
    Result =
        rebar3_backwater_util:lists_anymap(
          fun (SourceDirectory) ->
                  SourceFiles = directory_source_files(SourceDirectory),
                  ExpectedPrefix = filename:join(SourceDirectory, ModuleStr) ++ ".",
                  rebar3_backwater_util:lists_anymap(
                    fun (SourceFile) ->
                            length(SourceFile) =:= length(ExpectedPrefix) + 3
                            andalso lists:prefix(ExpectedPrefix, SourceFile)
                    end,
                    SourceFiles)
          end,
          SourceDirectories),

    case Result of
        {true, SourceFile} ->
            {ok, #{ module_path => SourceFile }};
        false ->
            {error, module_not_found}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
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
generate_backwater_code(GenerationParams) ->
    {ok, ModulePath, Forms} = read_forms(GenerationParams),
    ParseResult = lists:foldl(fun parse_module/2, dict:new(), Forms),
    ModuleInfo = generate_module_info(ModulePath, ParseResult),
    TransformedModuleInfo = transform_module(GenerationParams, ModuleInfo),
    write_module(GenerationParams, TransformedModuleInfo).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Parsing the Original Code
%% ------------------------------------------------------------------

%%
%% Based on forms[1] by Enrique Fernández, MIT License,
%% commit 491b6768dd9d4f2cd22a90327041b630f68dd66a
%%
%% [1]: https://github.com/efcasado/forms
%%
%-spec read_forms(atom() | iolist()) -> [erl_parse:abstract_form()].
read_forms(#{ module_name := Module })  ->
    ModulePath = code:which(Module),
    try beam_lib:chunks(ModulePath, [abstract_code]) of
        {ok, {Module, [{abstract_code, {raw_abstract_v1, Forms}}]}} ->
            {ok, ModulePath, Forms};
        {ok, {no_debug_info, _}} ->
            {error, forms_not_found};
        {error, beam_lib, {file_error, _, enoent}} ->
            {error, {module_not_found, Module}}
    catch
        Class:Error ->
            {error, {Class, Error}}
    end;
read_forms(#{ module_path := ModulePath }) ->
    try epp:parse_file(ModulePath, []) of
        {ok, Forms} ->
            {ok, ModulePath, Forms};
        {ok, Forms, _Extra} ->
            {ok, Forms};
        {error, enoent} ->
            {error, file_not_found}
    catch
        Class:Error ->
            {error, {Class, Error}}
    end.

parse_module({attribute, _Line, module, Module}, Acc) ->
    dict:store(module, Module, Acc);
parse_module({attribute, _Line, export, Pairs}, Acc) ->
    dict:append_list(exports, Pairs, Acc);
parse_module({attribute, _Line, export_type, Pairs}, Acc) ->
    dict:append_list(type_exports, Pairs, Acc);
parse_module({attribute, _Line, deprecated, Data}, Acc) when is_list(Data) ->
    dict:append_list(deprecation_attributes, Data, Acc);
parse_module({attribute, _Line, deprecated, Data}, Acc) ->
    dict:append(deprecation_attributes, Data, Acc);
parse_module({attribute, _Line, backwater_module_version, RawVersion}, Acc) ->
    case unicode:characters_to_list(RawVersion) of
        Version when is_list(Version) ->
            dict:store(backwater_module_version, Version, Acc)
    end;
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
    Acc.

generate_module_info(ModulePath, ParseResult) ->
    BaseModuleInfo =
        #{ original_path => ModulePath,
           exports => sets:new(),
           type_exports => sets:new(),
           deprecation_attributes => sets:new(),
           backwater_module_version => ?DEFAULT_BACKWATER_MODULE_VERSION,
           backwater_exports => sets:new(),
           function_specs => maps:new(),
           function_definitions => maps:new() },

    ModuleInfo =
        maps:from_list(
          dict:to_list(
            dict:map(
              fun (module, Module) ->
                      Module;
                  (exports, Exports) ->
                      sets:from_list(Exports);
                  (deprecation_attributes, DeprecationAttributes) ->
                      sets:from_list(DeprecationAttributes);
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

%% ------------------------------------------------------------------
%% Internal Function Definitions - Transforming the Code
%% ------------------------------------------------------------------

transform_module(GenerationParams, ModuleInfo1) ->
    ModuleInfo2 = transform_exports(GenerationParams, ModuleInfo1),
    ModuleInfo3 = trim_functions_and_specs(ModuleInfo2),
    ModuleInfo4 = externalize_function_specs_user_types(GenerationParams, ModuleInfo3),
    rename_module(ModuleInfo4).

transform_exports(GenerationParams, ModuleInfo1) ->
    #{ target_opts := TargetOpts } = GenerationParams,
    #{ exports := Exports1, backwater_exports := BackwaterExports } = ModuleInfo1,
    CommonExclusionList = [{module_info, 0}, {behaviour_info, 1}],
    Exports2 = sets:subtract(Exports1, sets:from_list(CommonExclusionList)),
    ModuleInfo2 = maps:remove(backwater_exports, ModuleInfo1),
    Exports3 =
        case proplists:get_value(exports, TargetOpts, ?DEFAULT_PARAM_EXPORTS)
        of
            all -> Exports2;
            use_backwater_attributes -> sets:intersection(Exports2, BackwaterExports);
            List when is_list(List) -> sets:intersection(Exports2, sets:from_list(List))
        end,
    ModuleInfo2#{ exports := Exports3 }.

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

write_module(GenerationParams, ModuleInfo) ->
    ClientRef = target_client_ref(GenerationParams),
    OutputDirectory = target_output_directory(GenerationParams),
    #{ module := Module } = ModuleInfo,
    ModuleFilename = filename:join(OutputDirectory, atom_to_list(Module) ++ ".erl"),
    ModuleSrc = generate_module_source(ClientRef, ModuleInfo),
    case file:write_file(ModuleFilename, ModuleSrc) of
        ok -> ok;
        {error, Error} -> error({couldnt_save_module, Error})
    end.

target_client_ref(GenerationParams) ->
    #{ target_opts := TargetOpts } = GenerationParams,
    proplists:get_value(client_ref, TargetOpts, ?DEFAULT_PARAM_CLIENT_REF).

target_output_directory(GenerationParams) ->
    #{ target_opts := TargetOpts } = GenerationParams,
    case proplists:get_value(output_directory, TargetOpts) of
        undefined ->
            #{ current_app_info := CurrentAppInfo } = GenerationParams,
            CurrentAppSourceDirectories = app_info_src_directories(CurrentAppInfo),
            hd(CurrentAppSourceDirectories);
        OutputDirectory ->
            OutputDirectory
    end.

externalize_function_specs_user_types(GenerationParams, ModuleInfo1) ->
    % do it
    #{ function_specs := FunctionSpecs1 } = ModuleInfo1,
    Acc1 = ModuleInfo1#{ missing_types_messages => sets:new() },
    {FunctionSpecs2, Acc2} =
        rebar3_backwater_util:maps_mapfold(
          fun externalize_function_spec_definitions_user_types/3,
          Acc1,
          FunctionSpecs1),
    #{ missing_types_messages := MissingTypesMessages } = Acc2,
    ModuleInfo2 = maps:without([missing_types_messages], Acc2),
    ModuleInfo3 = ModuleInfo2#{ function_specs => FunctionSpecs2 },

    % handle types and records warnings
    (sets:size(MissingTypesMessages) > 0 andalso
     begin
         #{ target_opts := TargetOpts } = GenerationParams,
         MissingTypesBehaviour =
            proplists:get_value(unexported_types, TargetOpts, ?DEFAULT_PARAM_UNEXPORTED_TYPES),
         MissingTypesMsgFunction = missing_type_msg_function(MissingTypesBehaviour),
         MissingTypesMessagesList = lists:sort( sets:to_list(MissingTypesMessages) ),
         FormattedMsg =
            lists:foldl(
              fun ({ModulePath, Line, Fmt, Args}, Acc) ->
                      [Acc, "\n", io_lib:format("~s:~p - " ++ Fmt, [ModulePath, Line | Args])]
              end,
              [],
              MissingTypesMessagesList),
         MissingTypesMsgFunction(FormattedMsg, [])
     end),

    ModuleInfo3.

externalize_function_spec_definitions_user_types({_Name, _Arity}, Definitions, Acc) ->
    lists:mapfoldl(fun externalize_user_types/2, Acc, Definitions).

externalize_user_types({type, Line, record, Args}, Acc1) ->
    {atom, _NameLine, Name} = hd(Args),
    Acc2 = handle_unexported_record_reference(Line, Name, Acc1),
    {{type, Line, term, []}, Acc2};
externalize_user_types({user_type, Line, Name, Args1}, Acc1) ->
    {Args2, Acc2} = externalize_user_types(Args1, Acc1),
    #{ module := Module, type_exports := TypeExports } = Acc2,
    Arity = length(Args2),
    Id = {Name, Arity},
    Acc3 =
        case sets:is_element(Id, TypeExports) of
            true -> Acc2;
            false -> handle_unexported_type(Line, Name, Arity, Acc2)
        end,
    {{remote_type, Line, [{atom, Line, Module}, {atom, Line, Name}, Args2]}, Acc3};
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
externalize_user_types({type, _Line, _Builtin} = T, Acc) ->
    {T, Acc};
externalize_user_types({var, _Line, _Name} = T, Acc) ->
    {T, Acc}.

handle_unexported_record_reference(Line, Name, Acc) ->
    maps:update_with(
      missing_types_messages,
      fun (Prev) ->
              #{ original_path := ModulePath } = Acc,
              Msg = {ModulePath, Line, "Reference to unexportable record #~p{}", [Name]},
              sets:add_element(Msg, Prev)
      end,
      Acc).

handle_unexported_type(Line, Name, Arity, Acc) ->
    maps:update_with(
      missing_types_messages,
      fun (Prev) ->
              #{ original_path := ModulePath } = Acc,
              Msg = {ModulePath, Line, "Reference to unexported type ~p/~p", [Name, Arity]},
              sets:add_element(Msg, Prev)
      end,
      Acc).

missing_type_msg_function(ignore) ->
    fun rebar_api:debug/2;
missing_type_msg_function(warn) ->
    fun rebar_api:warn/2;
missing_type_msg_function(error) ->
    fun rebar_api:error/2;
missing_type_msg_function(abort) ->
    fun rebar_api:abort/2.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Generating the New Code
%% ------------------------------------------------------------------

generate_module_source(ClientRef, ModuleInfo) ->
    Header = generate_module_source_header(ModuleInfo),
    Exports = generate_module_source_exports(ModuleInfo),
    XRefAttributes = generate_module_source_xref_attributes(ModuleInfo),
    FunctionSpecs = generate_module_source_function_specs(ModuleInfo),
    FunctionDefinitions = generate_module_source_function_definitions(ClientRef, ModuleInfo),

    [Header,
     generate_module_source_section("Exports", Exports),
     generate_module_source_section("Xref", XRefAttributes),
     generate_module_source_section("Specifications", FunctionSpecs),
     generate_module_source_section("Definitions", FunctionDefinitions)].

generate_module_source_header(ModuleInfo) ->
    #{ module := Module } = ModuleInfo,
    erl_pp:attribute({attribute, 0, module, Module}).

generate_module_source_exports(ModuleInfo) ->
    #{ exports := Exports } = ModuleInfo,
    ExportsList = lists:sort( sets:to_list(Exports) ),
    lists:map(
      fun ({Name, Arity}) ->
              erl_pp:attribute({attribute, ?DUMMY_LINE_NUMBER, export, [{Name, Arity}]})
      end,
      ExportsList).

generate_module_source_xref_attributes(ModuleInfo) ->
    #{ exports := Exports, deprecation_attributes := DeprecationAttributes } = ModuleInfo,
    ExportsList = lists:sort( sets:to_list(Exports) ),
    DeprecationAttributesList = lists:sort( sets:to_list(DeprecationAttributes) ),

    AbstractIgnoreAttributes =
        lists:map(
          fun ({Name, Arity}) ->
                  erl_pp:attribute({attribute, ?DUMMY_LINE_NUMBER, ignore_xref, {Name, Arity}})
          end,
          ExportsList),

    AbstractDeprecationAttributes =
        lists:map(
          fun (Data) ->
                  erl_pp:attribute({attribute, ?DUMMY_LINE_NUMBER, deprecated, Data})
          end,
          DeprecationAttributesList),

    [AbstractIgnoreAttributes,
     case AbstractIgnoreAttributes =/= [] andalso AbstractDeprecationAttributes =/= [] of
         true -> "\n";
         false -> ""
     end,
     AbstractDeprecationAttributes].

generate_module_source_function_specs(ModuleInfo) ->
    #{ function_definitions := FunctionDefinitions } = ModuleInfo,
    FunctionNameArities = lists:keysort(1, maps:keys(FunctionDefinitions)),
    List =
        lists:map(
          fun ({Name, Arity}) ->
                  generate_module_source_function_spec({Name, Arity}, ModuleInfo)
          end,
          FunctionNameArities),
    lists:join("\n", List).

generate_module_source_function_spec({Name, Arity}, ModuleInfo) ->
    #{ function_specs := FunctionSpecs } = ModuleInfo,
    Attribute =
        case maps:find({Name, Arity}, FunctionSpecs) of
            {ok, Definitions} ->
                WrappedDefinitions =
                    [wrap_function_spec_return_types(Definition) || Definition <- Definitions],
                {attribute, ?DUMMY_LINE_NUMBER, spec, {{Name, Arity}, WrappedDefinitions}};
            error ->
                Definition = generic_function_spec(Arity),
                {attribute, ?DUMMY_LINE_NUMBER, spec, {{Name, Arity}, [Definition]}}
        end,
    erl_pp:attribute(Attribute).

generate_module_source_function_definitions(ClientRef, ModuleInfo) ->
    #{ function_definitions := FunctionDefinitions } = ModuleInfo,
    FunctionDefinitionsList = lists:keysort(1, maps:to_list(FunctionDefinitions)),
    List =
        lists:map(
          fun (FunctionDefinitionKV) ->
                  generate_module_source_function(ClientRef, FunctionDefinitionKV, ModuleInfo)
          end,
          FunctionDefinitionsList),
    lists:join("\n", List).

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

generate_module_source_function(ClientRef, {{Name, Arity}, Definitions}, ModuleInfo) ->
    #{ original_module := OriginalModule,
       backwater_module_version := BackwaterModuleVersion } = ModuleInfo,
    IndexedVarLists = generate_module_source_indexed_var_lists(Definitions),
    ArgNames = generate_module_source_arg_names(Arity, IndexedVarLists),
    UniqueArgNames = generate_module_source_unique_arg_names(Arity, ArgNames),
    ArgVars = [{var, ?DUMMY_LINE_NUMBER, list_to_atom(StringName)} || StringName <- UniqueArgNames],
    Guards = [],
    Body = generate_module_source_function_body(
             ClientRef, OriginalModule, BackwaterModuleVersion, Name, ArgVars),
    Clause = {clause, ?DUMMY_LINE_NUMBER, ArgVars, Guards, Body},
    erl_pp:function({function, ?DUMMY_LINE_NUMBER, Name, Arity, [Clause]}).

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

generate_module_source_arg_names(Arity, IndexedVarLists) ->
    lists:map(
      fun ({Index, Vars}) ->
              ArgNames = filter_arg_names_from_function_vars(Vars),
              CleanArgNames = lists:map(fun clean_arg_name/1, ArgNames),
              ValidArgNames = lists:filter(fun is_valid_arg_name/1, CleanArgNames),
              UniqueArgNames1 = lists:usort(ValidArgNames),
              UniqueArgNames2 =
                case UniqueArgNames1 =:= [] of
                    true -> [generated_arg_name(Arity, Index)];
                    false -> UniqueArgNames1
                end,
              Concat = string:join(UniqueArgNames2, "_Or_"),
              case length(Concat) > 255 of % atom limit
                  true -> generated_arg_name(Arity, Index);
                  false -> Concat
              end
      end,
      IndexedVarLists).

filter_arg_names_from_function_vars(Vars) ->
    lists:foldr(
      fun F({var, _Line, AtomName}, Acc) ->
              [atom_to_list(AtomName) | Acc];
          F({match, _Line1, Left, Right}, Acc1) ->
              Acc2 = F(Right, Acc1),
              F(Left, Acc2);
          F(_Other, Acc) ->
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

generated_arg_name(FunctionArity, Index) when FunctionArity =:= 1, Index =:= 1 ->
    "Arg";
generated_arg_name(_FunctionArity, Index) ->
    "Arg" ++ integer_to_list(Index).

generate_module_source_unique_arg_names(Arity, ArgNames) ->
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
                                _ -> generated_arg_name(Arity, Index)
                            end,
                          {MappedArgName, Index + 1}
                  end,
                  1,
                  ArgNames),

            generate_module_source_unique_arg_names(Arity, MappedArgNames)
    end.

generate_module_source_function_body(ClientRef, OriginalModule, BackwaterModuleVersion, Name, ArgVars) ->
    [fully_qualified_call_clause(ClientRef, OriginalModule, BackwaterModuleVersion, Name, ArgVars)].

fully_qualified_call_clause(ClientRef, OriginalModule, BackwaterModuleVersion, Name, ArgVars) ->
    Call =
        {remote, ?DUMMY_LINE_NUMBER,
         {atom, ?DUMMY_LINE_NUMBER, backwater_client},
         {atom, ?DUMMY_LINE_NUMBER, call}},
    Args =
        [erl_syntax:revert( erl_syntax:abstract(ClientRef) ),
         {atom, ?DUMMY_LINE_NUMBER, OriginalModule},
         erl_syntax:revert( erl_syntax:abstract(BackwaterModuleVersion) ),
         {atom, ?DUMMY_LINE_NUMBER, Name},
         fully_qualified_call_clause_args(ArgVars)],
    {call, ?DUMMY_LINE_NUMBER, Call, Args}.

fully_qualified_call_clause_args([]) ->
    {nil, ?DUMMY_LINE_NUMBER};
fully_qualified_call_clause_args([H|T]) ->
    {cons, ?DUMMY_LINE_NUMBER, H, fully_qualified_call_clause_args(T)}.

generate_module_source_section(Comment, Data) ->
    case iolist_size(Data) =:= 0 of
        true -> "";
        false ->
            [generate_module_source_section_header_comment(Comment), Data]
    end.

generate_module_source_section_header_comment(Comment) ->
    Rule = "% ------------------------------------------------------------------",
    Forms = [erl_syntax:comment([Rule, "% " ++ Comment, Rule])],
    ["\n", erl_prettypr:format( erl_syntax:form_list(Forms) ), "\n"].
