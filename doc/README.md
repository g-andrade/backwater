

# backwater #

[![Build Status](https://travis-ci.org/g-andrade/backwater.png?branch=master)](https://travis-ci.org/g-andrade/backwater)

Backwater is an no-frills RPC framework for remote Erlang and Elixir modules,
built on top of [cowboy](https://github.com/ninenines/cowboy) and
[hackney](https://github.com/benoitc/hackney).

* Arbitrary modules can be wholly or partially exposed
* Which functions to expose/export can be specified using custom attributes (default behaviour)
* Module-specific wrappers for remote calls can be generated using a bundled rebar3 plugin (Erlang only)
* Arguments and return values are encoded using [External Term Format](http://erlang.org/doc/apps/erts/erl_ext_dist); unsafe arguments and return values are not decoded by default
* Multiple instances of both client and server can be launched and managed independently
* Remote exceptions are returned as errors but can be locally rethrown if so desired
* (Purged) stacktraces of remote exceptions are returned by default
* All calls and responses are authenticated and signed using a modified version of [HTTP signatures](https://tools.ietf.org/id/draft-cavage-http-signatures-07.txt); nevertheless, it's __strongly__ recommended to use HTTPS, as this doesn't protect against replay attacks (besides the potential exposure of sensitive data)

Requirements:
* Erlang/OTP 19 and up

The server start/stop interface is very similar to cowboy's, and all cowboy settings, excluding routing, are available for tweaking.

The client interface is made up of start/stop calls for management and an apply/3-esque function; hackney settings can be arbitrarily tweaked or overridden.

The rebar3 code generation plugin is still not as polished as it could be but it works fairly well.

Some simple examples are under 'examples/'; for all possible configuration options, check the [documentation](#modules).


### <a name="Example_1_-_Remote_'string'_module_and_client_code_generation_(Erlang)">Example 1 - Remote 'string' module and client code generation (Erlang)</a> ###


#### <a name="1.1._Configure_dependencies_and_the_rebar3_plugin">1.1. Configure dependencies and the rebar3 plugin</a> ####


```erlang

% rebar.config
{backwater_gen,
 [{client_ref, example1},
  {target, {stdlib, string, [{exports,all}]}}]}.

{deps, [{backwater, "1.0.0"}]}.
{plugins, [{backwater, "1.0.0"}]}.

```


#### <a name="1.2._Generate_the_wrapper_code">1.2. Generate the wrapper code</a> ####


```

$ rebar3 backwater generate
# "src/rpc/rpc_string.erl" will be created

```


#### <a name="1.3._Generate_unique_secret">1.3. Generate unique secret</a> ####


```erlang

Secret = crypto:strong_rand_bytes(32).

```


#### <a name="1.4._Start_server">1.4. Start server</a> ####


```erlang

% Place this where appropriate e.g. on application start/2 callback
{ok, _Pid} =
    backwater_server:start_clear(
        example1,
        #{ secret => Secret,
           exposed_modules => [{string, [{exports,all}]] },
        [{port, 8080}],
        #{}).

```


#### <a name="1.5._Start_client">1.5. Start client</a> ####


```erlang

% Place this where appropriate e.g. on application start/2 callback
ok = backwater_client:start(
        example1,
        #{ endpoint => <<"http://127.0.0.1:8080/">>,
           secret => Secret }).

```


#### <a name="1.6._Execute_remote_calls_using_the_generated_code">1.6. Execute remote calls using the generated code</a> ####


```erlang

{ok, 5} = rpc_string:length("hello"),
{ok, {3.14, ""}} = rpc_string:to_float("3.14").

```


### <a name="Example_2_-_A_remote_simple_calculator_using_Kernel_functions_(Elixir)">Example 2 - A remote simple calculator using Kernel functions (Elixir)</a> ###


#### <a name="2.1._Add_backwater_dependency_to_Mix">2.1. Add backwater dependency to Mix</a> ####


```elixir

#mix.exs
# [...]
  defp deps do
    [{:backwater, "-> 1.0"}]
  end
# [...]

```


#### <a name="2.2._Generate_unique_secret">2.2. Generate unique secret</a> ####


```elixir

secret = :crypto.strong_rand_bytes(32)

```


#### <a name="2.3._Start_server">2.3. Start server</a> ####


```elixir

{:ok, _pid} =
    :backwater_server.start_clear(
        :example2,
        %{ :secret => secret,
           :exposed_modules => [{Kernel, [{:exports, [:+, :-, :*, :/]}]}] },
        [{:port, 8080}],
        %{})

```


#### <a name="2.4_Start_client">2.4 Start client</a> ####


```elixir

:ok = backwater_client.start(
        :example2,
        %{ :endpoint => "http://127.0.0.1:8080/",
           :secret => secret })

```


#### <a name="2.5_Execute_remote_calls">2.5 Execute remote calls</a> ####


```elixir

{:ok, 5}   = :backwater_client.call(:example2, :+, [3, 2])
{:ok, 1}   = :backwater_client.call(:example2, :-, [3, 2])
{:ok, 6}   = :backwater_client.call(:example2, :*, [3, 2])
{:ok, 1.5} = :backwater_client.call(:example2, :/, [3, 2])

```


### <a name="Example_3_-_Exposure_of_a_module_using_custom_attributes_(Erlang)">Example 3 - Exposure of a module using custom attributes (Erlang)</a> ###


#### <a name="3.1._Add_backwater_dependency_to_rebar3">3.1. Add backwater dependency to rebar3</a> ####


```erlang

% rebar.config
{deps, [{backwater, "1.0.0"}]}.

```


#### <a name="3.2._Add_custom_attributes_to_module_within_your_application">3.2. Add custom attributes to module within your application</a> ####


```erlang

% foobar.erl
-module(foobar)
-export([hello/0, increment/1]).

% The custom export attribute
-backwater_export({hello,0}).
-backwater_export({increment,1}).

hello() -> world.

increment(Number) -> Number + 3.

```


#### <a name="3.3._Generate_unique_secret">3.3. Generate unique secret</a> ####


```erlang

Secret = crypto:strong_rand_bytes(32).

```


#### <a name="3.4._Start_server">3.4. Start server</a> ####


```erlang

% Place this where appropriate e.g. on application start/2 callback
{ok, _Pid} =
    backwater_server:start_clear(
        example3,
        #{ secret => Secret,
           exposed_modules => [foobar] }, % function exposure is determined by attributes
        [{port, 8080}],
        #{}).

```


#### <a name="3.5._Start_client">3.5. Start client</a> ####


```erlang

% Place this where appropriate e.g. on application start/2 callback
ok = backwater_client:start(
        example3,
        #{ endpoint => <<"http://127.0.0.1:8080/">>,
           secret => Secret }).

```


#### <a name="3.6._Execute_remote_calls">3.6. Execute remote calls</a> ####


```erlang

{ok, world} = backwater_client:call(foobar, hello, []),
{ok, 43} = backwater_client:call(foobar, increment, [42]).

```



## Modules ##


<table width="100%" border="0" summary="list of modules">
<tr><td><a href="backwater_client.md" class="module">backwater_client</a></td></tr>
<tr><td><a href="backwater_cowboy_handler.md" class="module">backwater_cowboy_handler</a></td></tr>
<tr><td><a href="backwater_http_request.md" class="module">backwater_http_request</a></td></tr>
<tr><td><a href="backwater_http_response.md" class="module">backwater_http_response</a></td></tr>
<tr><td><a href="backwater_http_signatures.md" class="module">backwater_http_signatures</a></td></tr>
<tr><td><a href="backwater_module_info.md" class="module">backwater_module_info</a></td></tr>
<tr><td><a href="backwater_rebar3_generator.md" class="module">backwater_rebar3_generator</a></td></tr>
<tr><td><a href="backwater_server.md" class="module">backwater_server</a></td></tr>
<tr><td><a href="backwater_util.md" class="module">backwater_util</a></td></tr></table>

