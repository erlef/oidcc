-ifndef(OIDCC_CLIENT_REGISTRATION_HRL).

%% @see https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
-record(oidcc_client_registration, {
    redirect_uris :: [uri_string:uri_string()],
    response_types = undefined :: [binary()] | undefined,
    grant_types = undefined :: [binary()] | undefined,
    application_type = web :: web | native,
    contacts = undefined :: [binary()] | undefined,
    client_name = undefined :: binary() | undefined,
    logo_uri = undefined :: uri_string:uri_string() | undefined,
    client_uri = undefined :: uri_string:uri_string() | undefined,
    policy_uri = undefined :: uri_string:uri_string() | undefined,
    tos_uri = undefined :: uri_string:uri_string() | undefined,
    jwks = undefined :: jose_jwk:key() | undefined,
    jwks_uri = undefined :: uri_string:uri_string() | undefined,
    sector_identifier_uri = undefined :: uri_string:uri_string() | undefined,
    subject_type = undefined :: pairwise | public | undefined,
    id_token_signed_response_alg = undefined :: binary() | undefined,
    id_token_encrypted_response_alg = undefined :: binary() | undefined,
    id_token_encrypted_response_enc = undefined :: binary() | undefined,
    userinfo_signed_response_alg = undefined :: binary() | undefined,
    userinfo_encrypted_response_alg = undefined :: binary() | undefined,
    userinfo_encrypted_response_enc = undefined :: binary() | undefined,
    request_object_signing_alg = undefined :: binary() | undefined,
    request_object_encryption_alg = undefined :: binary() | undefined,
    request_object_encryption_enc = undefined :: binary() | undefined,
    token_endpoint_auth_method = <<"client_secret_basic">> :: erlang:binary(),
    token_endpoint_auth_signing_alg = undefined :: binary() | undefined,
    default_max_age = undefined :: pos_integer() | undefined,
    require_auth_time = false :: boolean(),
    default_acr_values = undefined :: [binary()] | undefined,
    initiate_login_uri = undefined :: uri_string:uri_string() | undefined,
    request_uris = undefined :: [uri_string:uri_string()] | undefined,
    %% Unknown Fields
    extra_fields = #{} :: #{binary() => term()}
}).

%% @see https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse
-record(oidcc_client_registration_response, {
    client_id :: erlang:binary(),
    client_secret = undefined :: binary() | undefined,
    registration_access_token = undefined :: binary() | undefined,
    registration_client_uri = undefined :: uri_string:uri_string() | undefined,
    client_id_issued_at = undefined :: pos_integer() | undefined,
    client_secret_expires_at = undefined :: pos_integer() | undefined,
    %% Unknown Fields
    extra_fields = #{} :: #{binary() => term()}
}).

-define(OIDCC_CLIENT_REGISTRATION_HRL, 1).

-endif.
