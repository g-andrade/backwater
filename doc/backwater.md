

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




### <a name="type-proto_opts">proto_opts()</a> ###


<pre><code>
proto_opts() = <a href="cowboy_http.md#type-opts">cowboy_http:opts()</a> | [{atom(), term()}]
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


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#call-4">call/4</a></td><td></td></tr><tr><td valign="top"><a href="#call-5">call/5</a></td><td></td></tr><tr><td valign="top"><a href="#start_clear_listener-1">start_clear_listener/1</a></td><td></td></tr><tr><td valign="top"><a href="#start_clear_listener-4">start_clear_listener/4</a></td><td></td></tr><tr><td valign="top"><a href="#start_tls_listener-2">start_tls_listener/2</a></td><td></td></tr><tr><td valign="top"><a href="#start_tls_listener-4">start_tls_listener/4</a></td><td></td></tr><tr><td valign="top"><a href="#stop_listener-0">stop_listener/0</a></td><td></td></tr><tr><td valign="top"><a href="#stop_listener-1">stop_listener/1</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="call-4"></a>

### call/4 ###

<pre><code>
call(Endpoint, Module, Function, Args) -&gt; Result | no_return()
</code></pre>

<ul class="definitions"><li><code>Endpoint = <a href="backwater_request.md#type-endpoint">backwater_request:endpoint()</a></code></li><li><code>Module = module()</code></li><li><code>Function = atom()</code></li><li><code>Args = [term()]</code></li><li><code>Result = <a href="#type-call_result">call_result()</a></code></li></ul>

<a name="call-5"></a>

### call/5 ###

<pre><code>
call(Endpoint, Module, Function, Args, Options) -&gt; Result | no_return()
</code></pre>

<ul class="definitions"><li><code>Endpoint = <a href="backwater_request.md#type-endpoint">backwater_request:endpoint()</a></code></li><li><code>Module = module()</code></li><li><code>Function = atom()</code></li><li><code>Args = [term()]</code></li><li><code>Options = <a href="#type-call_opts">call_opts()</a></code></li><li><code>Result = <a href="#type-call_result">call_result()</a></code></li></ul>

<a name="start_clear_listener-1"></a>

### start_clear_listener/1 ###

<pre><code>
start_clear_listener(Config) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Config = <a href="backwater_cowboy_handler.md#type-config">backwater_cowboy_handler:config()</a></code></li></ul>

<a name="start_clear_listener-4"></a>

### start_clear_listener/4 ###

<pre><code>
start_clear_listener(Ref, Config, TransportOpts, ProtoOpts) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li><li><code>Config = <a href="backwater_cowboy_handler.md#type-config">backwater_cowboy_handler:config()</a></code></li><li><code>TransportOpts = <a href="#type-clear_opts">clear_opts()</a></code></li><li><code>ProtoOpts = <a href="#type-proto_opts">proto_opts()</a></code></li></ul>

<a name="start_tls_listener-2"></a>

### start_tls_listener/2 ###

<pre><code>
start_tls_listener(Config, TransportOpts) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Config = <a href="backwater_cowboy_handler.md#type-config">backwater_cowboy_handler:config()</a></code></li><li><code>TransportOpts = <a href="#type-tls_opts">tls_opts()</a></code></li></ul>

<a name="start_tls_listener-4"></a>

### start_tls_listener/4 ###

<pre><code>
start_tls_listener(Ref, Config, TransportOpts, ProtoOpts) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li><li><code>Config = <a href="backwater_cowboy_handler.md#type-config">backwater_cowboy_handler:config()</a></code></li><li><code>TransportOpts = <a href="#type-tls_opts">tls_opts()</a></code></li><li><code>ProtoOpts = <a href="#type-proto_opts">proto_opts()</a></code></li></ul>

<a name="stop_listener-0"></a>

### stop_listener/0 ###

<pre><code>
stop_listener() -&gt; ok | {error, not_found}
</code></pre>
<br />

<a name="stop_listener-1"></a>

### stop_listener/1 ###

<pre><code>
stop_listener(Ref) -&gt; ok | {error, not_found}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li></ul>

