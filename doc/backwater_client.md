

# Module backwater_client #
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

__References__*

* hackney request options listed [here](https://github.com/benoitc/hackney/blob/master/doc/hackney.md)

<a name="types"></a>

## Data Types ##




### <a name="type-hackney_error">hackney_error()</a> ###


<pre><code>
hackney_error() = {hackney, term()}
</code></pre>




### <a name="type-hackney_option">hackney_option()</a> ###


<pre><code>
hackney_option() = <a href="proplists.md#type-property">proplists:property()</a>
</code></pre>




### <a name="type-options">options()</a> ###


<pre><code>
options() = #{hackney_opts =&gt; [<a href="#type-hackney_option">hackney_option()</a>], compression_threshold =&gt; non_neg_integer(), connect_timeout =&gt; timeout(), decode_unsafe_terms =&gt; boolean(), max_encoded_result_size =&gt; non_neg_integer(), recv_timeout =&gt; timeout(), rethrow_remote_exceptions =&gt; boolean()}
</code></pre>




### <a name="type-result">result()</a> ###


<pre><code>
result() = <a href="backwater_response.md#type-t">backwater_response:t</a>(<a href="#type-hackney_error">hackney_error()</a> | not_started)
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#call-4">call/4</a></td><td></td></tr><tr><td valign="top"><a href="#call-5">call/5</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="call-4"></a>

### call/4 ###

<pre><code>
call(Endpoint, Module, Function, Args) -&gt; Result | no_return()
</code></pre>

<ul class="definitions"><li><code>Endpoint = <a href="backwater_request.md#type-endpoint">backwater_request:endpoint()</a></code></li><li><code>Module = module()</code></li><li><code>Function = atom()</code></li><li><code>Args = [term()]</code></li><li><code>Result = <a href="#type-result">result()</a></code></li></ul>

<a name="call-5"></a>

### call/5 ###

<pre><code>
call(Endpoint, Module, Function, Args, Options) -&gt; Result | no_return()
</code></pre>

<ul class="definitions"><li><code>Endpoint = <a href="backwater_request.md#type-endpoint">backwater_request:endpoint()</a></code></li><li><code>Module = module()</code></li><li><code>Function = atom()</code></li><li><code>Args = [term()]</code></li><li><code>Options = <a href="#type-options">options()</a></code></li><li><code>Result = <a href="#type-result">result()</a></code></li></ul>

