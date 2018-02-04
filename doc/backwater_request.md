

# Module backwater_request #
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

<a name="types"></a>

## Data Types ##




### <a name="type-conn_params">conn_params()</a> ###


<pre><code>
conn_params() = #{transport =&gt; <a href="#type-transport">transport()</a>, host =&gt; nonempty_string(), port =&gt; <a href="inet.md#type-port_number">inet:port_number()</a>}
</code></pre>




### <a name="type-endpoint">endpoint()</a> ###


<pre><code>
endpoint() = {<a href="#type-location">location()</a>, <a href="#type-secret">secret()</a>}
</code></pre>




### <a name="type-http_params">http_params()</a> ###


<pre><code>
http_params() = #{method =&gt; <a href="#type-nonempty_binary">nonempty_binary()</a>, path =&gt; <a href="#type-nonempty_binary">nonempty_binary()</a>, headers =&gt; <a href="#type-nonempty_headers">nonempty_headers()</a>, body =&gt; binary()}
</code></pre>




### <a name="type-location">location()</a> ###


<pre><code>
location() = <a href="#type-nonempty_binary">nonempty_binary()</a>
</code></pre>




### <a name="type-nonempty_headers">nonempty_headers()</a> ###


<pre><code>
nonempty_headers() = [{<a href="#type-nonempty_binary">nonempty_binary()</a>, binary()}, ...]
</code></pre>




### <a name="type-options">options()</a> ###


<pre><code>
options() = #{compression_threshold =&gt; non_neg_integer()}
</code></pre>




### <a name="type-secret">secret()</a> ###


<pre><code>
secret() = binary()
</code></pre>




### <a name="type-state">state()</a> ###


<pre><code>
state() = #{signed_request_msg =&gt; <a href="backwater_signatures.md#type-signed_message">backwater_signatures:signed_message()</a>}
</code></pre>




### <a name="type-t">t()</a> ###


<pre><code>
t() = #{conn_params =&gt; <a href="#type-conn_params">conn_params()</a>, http_params =&gt; <a href="#type-http_params">http_params()</a>, full_url =&gt; <a href="#type-nonempty_binary">nonempty_binary()</a>}
</code></pre>




### <a name="type-transport">transport()</a> ###


<pre><code>
transport() = hackney_tcp | hackney_ssl
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#encode-4">encode/4</a></td><td></td></tr><tr><td valign="top"><a href="#encode-5">encode/5</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="encode-4"></a>

### encode/4 ###

<pre><code>
encode(Endpoint, Module, Function, Args) -&gt; {Request, RequestState}
</code></pre>

<ul class="definitions"><li><code>Endpoint = <a href="#type-endpoint">endpoint()</a></code></li><li><code>Module = module()</code></li><li><code>Function = atom()</code></li><li><code>Args = [term()]</code></li><li><code>Request = <a href="#type-t">t()</a></code></li><li><code>RequestState = <a href="#type-state">state()</a></code></li></ul>

<a name="encode-5"></a>

### encode/5 ###

<pre><code>
encode(Endpoint, Module, Function, Args, Options) -&gt; {Request, RequestState}
</code></pre>

<ul class="definitions"><li><code>Endpoint = <a href="#type-endpoint">endpoint()</a></code></li><li><code>Module = module()</code></li><li><code>Function = atom()</code></li><li><code>Args = [term()]</code></li><li><code>Options = <a href="#type-options">options()</a></code></li><li><code>Request = <a href="#type-t">t()</a></code></li><li><code>RequestState = <a href="#type-state">state()</a></code></li></ul>

