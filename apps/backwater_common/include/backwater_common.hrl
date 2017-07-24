-type nonempty_binary() :: <<_:8,_:_*8>>.
-export_type([nonempty_binary/0]).

-define(OPAQUE_BINARY(B), <<(B)/binary>>). % don't let Dialyzer be too smart
