-ifndef(OIDCC_TOKEN_INTROSPECTION_HRL).

-record(oidcc_token_introspection, {
    active :: boolean(),
    client_id :: binary(),
    exp :: pos_integer(),
    scope :: oidcc_scope:scopes(),
    username :: binary()
}).

-define(OIDCC_TOKEN_INTROSPECTION_HRL, 1).

-endif.
