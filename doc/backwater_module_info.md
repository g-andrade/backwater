

# Module backwater_module_info #
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

<a name="types"></a>

## Data Types ##




### <a name="type-content_type">content_type()</a> ###


<pre><code>
content_type() = {<a href="#type-nonempty_binary">nonempty_binary()</a>, <a href="#type-nonempty_binary">nonempty_binary()</a>}
</code></pre>




### <a name="type-exports">exports()</a> ###


<pre><code>
exports() = #{<a href="#type-fun_arity_pair">fun_arity_pair()</a> =&gt; <a href="#type-fun_properties">fun_properties()</a>}
</code></pre>




### <a name="type-exposed_module">exposed_module()</a> ###


<pre><code>
exposed_module() = module() | {module(), [<a href="#type-exposed_module_opt">exposed_module_opt()</a>]}
</code></pre>




### <a name="type-exposed_module_opt">exposed_module_opt()</a> ###


<pre><code>
exposed_module_opt() = {exports, all | [atom()]}
</code></pre>




### <a name="type-fun_arity_pair">fun_arity_pair()</a> ###


<pre><code>
fun_arity_pair() = {binary(), arity()}
</code></pre>




### <a name="type-fun_properties">fun_properties()</a> ###


<pre><code>
fun_properties() = #{known_content_types =&gt; [<a href="#type-content_type">content_type()</a>, ...], function_ref =&gt; function()}
</code></pre>




### <a name="type-lookup_result">lookup_result()</a> ###


<pre><code>
lookup_result() = {true, {BinModule::<a href="#type-nonempty_binary">nonempty_binary()</a>, <a href="#type-module_info">module_info()</a>}} | false
</code></pre>




### <a name="type-module_info">module_info()</a> ###


<pre><code>
module_info() = #{exports =&gt; <a href="#type-exports">exports()</a>}
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#metadata_export_list-0">metadata_export_list/0</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="metadata_export_list-0"></a>

### metadata_export_list/0 ###

<pre><code>
metadata_export_list() -&gt; [{atom(), arity()}]
</code></pre>
<br />

