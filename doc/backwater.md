

# Module backwater #
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

__References__*

* [ranch:opt()](https://ninenines.eu/docs/en/ranch/1.4/manual/ranch/#_opt) documentation
* [ranch_tcp:opt()](https://ninenines.eu/docs/en/ranch/1.4/manual/ranch_tcp/#_opt) documentation
* [ranch_ssl:opt()](https://ninenines.eu/docs/en/ranch/1.4/manual/ranch_ssl/#_opt_ranch_tcp_opt_ssl_opt) documentation
* [cowboy_http:opts()](https://ninenines.eu/docs/en/cowboy/2.0/manual/cowboy_http/#_options) documentation
* hackney request options listed [here](https://github.com/benoitc/hackney/blob/master/doc/hackney.md)

<a name="types"></a>

## Data Types ##




### <a name="type-call_opts">call_opts()</a> ###


<pre><code>
call_opts() = #{hackney_opts =&gt; [<a href="#type-hackney_option">hackney_option()</a>], compression_threshold =&gt; non_neg_integer(), connect_timeout =&gt; timeout(), decode_unsafe_terms =&gt; boolean(), max_encoded_result_size =&gt; non_neg_integer(), recv_timeout =&gt; timeout(), rethrow_remote_exceptions =&gt; boolean()}
</code></pre>




### <a name="type-call_result">call_result()</a> ###


<pre><code>
call_result() = <a href="backwater_response.md#type-t">backwater_response:t</a>(<a href="#type-hackney_error">hackney_error()</a>)
</code></pre>




### <a name="type-clear_opt">clear_opt()</a> ###


<pre><code>
clear_opt() = <a href="ranch.md#type-opt">ranch:opt()</a> | <a href="ranch_tcp.md#type-opt">ranch_tcp:opt()</a>
</code></pre>




### <a name="type-clear_opts">clear_opts()</a> ###


<pre><code>
clear_opts() = [<a href="#type-clear_opt">clear_opt()</a>]
</code></pre>




### <a name="type-hackney_error">hackney_error()</a> ###


<pre><code>
hackney_error() = {hackney, term()}
</code></pre>




### <a name="type-hackney_option">hackney_option()</a> ###


<pre><code>
hackney_option() = <a href="proplists.md#type-property">proplists:property()</a>
</code></pre>




### <a name="type-http_opts">http_opts()</a> ###


<pre><code>
http_opts() = <a href="cowboy_http.md#type-opts">cowboy_http:opts()</a> | [{atom(), term()}]
</code></pre>

for (reasonable) retro-compatibility with cowboy 1.x



### <a name="type-tls_opt">tls_opt()</a> ###


<pre><code>
tls_opt() = <a href="ranch.md#type-opt">ranch:opt()</a> | <a href="ranch_ssl.md#type-opt">ranch_ssl:opt()</a>
</code></pre>




### <a name="type-tls_opts">tls_opts()</a> ###


<pre><code>
tls_opts() = [<a href="#type-tls_opt">tls_opt()</a>]
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#call-4">call/4</a></td><td>Performs remote call on <code>Endpoint</code>.</td></tr><tr><td valign="top"><a href="#call-5">call/5</a></td><td>Performs remote call on <code>Endpoint</code>.</td></tr><tr><td valign="top"><a href="#start_clear_server-2">start_clear_server/2</a></td><td>Starts a cleartext cowboy listener that can handle remote calls.</td></tr><tr><td valign="top"><a href="#start_clear_server-4">start_clear_server/4</a></td><td>Like <code>:start_clear_server/2</code> but one can specify the listener name  and tune settings.</td></tr><tr><td valign="top"><a href="#start_tls_server-3">start_tls_server/3</a></td><td>Starts a TLS cowboy listener that can handle remote calls.</td></tr><tr><td valign="top"><a href="#start_tls_server-4">start_tls_server/4</a></td><td>Like <code>:start_tls_server/3</code> but one can specify the listener name and tune (more) settings.</td></tr><tr><td valign="top"><a href="#stop_server-0">stop_server/0</a></td><td>Stops the cowboy listener under the default name.</td></tr><tr><td valign="top"><a href="#stop_server-1">stop_server/1</a></td><td>Stops the cowboy listener under a specific name.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="call-4"></a>

### call/4 ###

<pre><code>
call(Endpoint, Module, Function, Args) -&gt; Result | no_return()
</code></pre>

<ul class="definitions"><li><code>Endpoint = <a href="backwater_request.md#type-endpoint">backwater_request:endpoint()</a></code></li><li><code>Module = module()</code></li><li><code>Function = atom()</code></li><li><code>Args = [term()]</code></li><li><code>Result = <a href="#type-call_result">call_result()</a></code></li></ul>

Performs remote call on `Endpoint`.

Returns:
- `{ok, ReturnValue}` in case of success
- `{error, term()}` otherwise.

__See also:__ [call/5](#call-5).

<a name="call-5"></a>

### call/5 ###

<pre><code>
call(Endpoint, Module, Function, Args, Options) -&gt; Result | no_return()
</code></pre>

<ul class="definitions"><li><code>Endpoint = <a href="backwater_request.md#type-endpoint">backwater_request:endpoint()</a></code></li><li><code>Module = module()</code></li><li><code>Function = atom()</code></li><li><code>Args = [term()]</code></li><li><code>Options = <a href="#type-call_opts">call_opts()</a></code></li><li><code>Result = <a href="#type-call_result">call_result()</a></code></li></ul>

Performs remote call on `Endpoint`.

Returns:
- `{ok, ReturnValue}` in case of success
- `{error, term()}` otherwise.

__See also:__ [call/4](#call-4).

<a name="start_clear_server-2"></a>

### start_clear_server/2 ###

<pre><code>
start_clear_server(Secret, ExposedModules) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Secret = binary()</code></li><li><code>ExposedModules = [<a href="backwater_module_exposure.md#type-t">backwater_module_exposure:t()</a>]</code></li></ul>

Starts a cleartext cowboy listener that can handle remote calls.

Returns:
- `{ok, ServerPid}` in case of success
- `{error, term()}` otherwise.

__See also:__ [start_clear_server/4](#start_clear_server-4).

<a name="start_clear_server-4"></a>

### start_clear_server/4 ###

<pre><code>
start_clear_server(Ref, Secret, ExposedModules, Opts) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li><li><code>Secret = binary()</code></li><li><code>ExposedModules = [<a href="backwater_module_exposure.md#type-t">backwater_module_exposure:t()</a>]</code></li><li><code>Opts = <a href="backwater_cowboy_handler.md#type-opts">backwater_cowboy_handler:opts</a>(<a href="#type-clear_opts">clear_opts()</a>, <a href="#type-http_opts">http_opts()</a>)</code></li></ul>

Like `:start_clear_server/2` but one can specify the listener name  and tune settings.

Returns:
- `{ok, ServerPid}` in case of success
- `{error, term()}` otherwise.

__See also:__ [start_clear_server/2](#start_clear_server-2).

<a name="start_tls_server-3"></a>

### start_tls_server/3 ###

<pre><code>
start_tls_server(Secret, ExposedModules, TLSOpts) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Secret = binary()</code></li><li><code>ExposedModules = [<a href="backwater_module_exposure.md#type-t">backwater_module_exposure:t()</a>]</code></li><li><code>TLSOpts = <a href="#type-tls_opts">tls_opts()</a></code></li></ul>

Starts a TLS cowboy listener that can handle remote calls.

Returns:
- `{ok, ServerPid}` in case of success
- `{error, term()}` otherwise.

__See also:__ [start_tls_server/4](#start_tls_server-4).

<a name="start_tls_server-4"></a>

### start_tls_server/4 ###

<pre><code>
start_tls_server(Ref, Secret, ExposedModules, Opts) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li><li><code>Secret = binary()</code></li><li><code>ExposedModules = [<a href="backwater_module_exposure.md#type-t">backwater_module_exposure:t()</a>]</code></li><li><code>Opts = <a href="backwater_cowboy_handler.md#type-opts">backwater_cowboy_handler:opts</a>(<a href="#type-tls_opts">tls_opts()</a>, <a href="#type-http_opts">http_opts()</a>)</code></li></ul>

Like `:start_tls_server/3` but one can specify the listener name and tune (more) settings.

Returns:
- `{ok, ServerPid}` in case of success
- `{error, term()}` otherwise.

__See also:__ [start_tls_server/3](#start_tls_server-3).

<a name="stop_server-0"></a>

### stop_server/0 ###

<pre><code>
stop_server() -&gt; ok | {error, not_found}
</code></pre>
<br />

Stops the cowboy listener under the default name.

<a name="stop_server-1"></a>

### stop_server/1 ###

<pre><code>
stop_server(Ref) -&gt; ok | {error, not_found}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li></ul>

Stops the cowboy listener under a specific name.

