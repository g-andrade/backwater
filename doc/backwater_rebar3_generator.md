

# Module backwater_rebar3_generator #
* [Data Types](#types)

<a name="types"></a>

## Data Types ##




### <a name="type-opt">opt()</a> ###


<pre><code>
opt() = {target, <a href="#type-target">target()</a>} | <a href="#type-overridable_opt">overridable_opt()</a>
</code></pre>




### <a name="type-overridable_opt">overridable_opt()</a> ###


<pre><code>
overridable_opt() = {client_ref, term()} | {module_name_prefix, <a href="file.md#type-name_all">file:name_all()</a>} | {module_name_suffix, <a href="file.md#type-name_all">file:name_all()</a>} | {unexported_types, ignore | warn | error | abort} | {output_src_dir, <a href="file.md#type-name_all">file:name_all()</a>}
</code></pre>




### <a name="type-target">target()</a> ###


<pre><code>
target() = module() | {module(), [<a href="#type-target_opt">target_opt()</a>]} | {AppName::atom(), module()} | {AppName::atom(), module(), [<a href="#type-target_opt">target_opt()</a>]}
</code></pre>




### <a name="type-target_exports">target_exports()</a> ###


<pre><code>
target_exports() = all | use_backwater_attributes | [atom()]
</code></pre>




### <a name="type-target_module_opt">target_module_opt()</a> ###


<pre><code>
target_module_opt() = {exports, <a href="#type-target_exports">target_exports()</a>}
</code></pre>




### <a name="type-target_opt">target_opt()</a> ###


<pre><code>
target_opt() = <a href="#type-target_module_opt">target_module_opt()</a> | <a href="#type-overridable_opt">overridable_opt()</a>
</code></pre>

