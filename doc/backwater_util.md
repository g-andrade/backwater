

# Module backwater_util #
* [Data Types](#types)

<a name="types"></a>

## Data Types ##




### <a name="type-config_validation_error">config_validation_error()</a> ###


<pre><code>
config_validation_error() = {invalid_config_parameter, {Key::term(), Value::term()}} | {missing_mandatory_config_parameters, [Key::term(), ...]} | config_not_a_map
</code></pre>




### <a name="type-proplist">proplist()</a> ###


<pre><code>
proplist() = [<a href="proplists.md#type-property">proplists:property()</a>]
</code></pre>

