# Conformance Testing

## Setup

- Register on https://www.certification.openid.net/
- Create Testplan https://www.certification.openid.net/schedule-test.html

## Conformance Profiles to Test

### OpenID Connect Core: Basic Certification Profile Relying Party Tests

- **Relevant for Certification: Yes**
- Id: `oidcc-client-basic-certification-test-plan`
- Request Type: `plain_http_request`
- Client Registration Type: `static_client`
- Config

```json
{
  "alias": "test",
  "description": "test",
  "client": {
    "client_id": "client_id",
    "client_secret": "client_secret",
    "redirect_uri": "http://localhost:4000/callback"
  }
}
```

### OpenID Connect Core Client Tests: Comprehensive client test

- **Relevant for Certification: No**
- Expected Failures
  - `oidcc-client-test-discovery-webfinger-acct` - WebFinger is not supported
  - `oidcc-client-test-discovery-webfinger-url` - Webfinger is not supported
- Id: `oidcc-client-test-plan`
- Client Authentication Type: `client_secret_post`
- Request Type: `plain_http_request`
- Response Type: `code`
- Client Registration Type: `static_client`
- Response Mode: `default`
- Config

```json
{
  "alias": "test",
  "description": "test",
  "client": {
    "client_id": "client_id",
    "client_secret": "client_secret",
    "redirect_uri": "http://localhost:4000/callback"
  }
}
```

### OpenID Connect Core Client Refresh Token Profile Tests: Relying party refresh token tests

- **Relevant for Certification: No**
- Id: `oidcc-client-refreshtoken-test-plan`
- Client Authentication Type: `client_secret_basic`
- Request Type: `plain_http_request`
- Response Type: `code`
- Client Registration Type: `static_client`
- Response Mode: `form_post`
- Config

```json
{
  "alias": "test",
  "description": "test",
  "client": {
    "client_id": "client_id",
    "client_secret": "client_secret",
    "redirect_uri": "http://localhost:4000/callback"
  }
}
```

### OpenID Connect Core: Form Post Basic Certification Profile Relying Party Tests

- **Relevant for Certification: Yes**
- Id: `oidcc-client-formpost-basic-certification-test-plan`
- Request Type: `plain_http_request`
- Client Registration Type: `static_client`
- Config

```json
{
  "alias": "test",
  "description": "test",
  "client": {
    "client_id": "client_id",
    "client_secret": "client_secret",
    "redirect_uri": "http://localhost:4000/callback"
  }
}
```

## How to Execute

- Open Plan / Specific Test
- Start `./test.exs`
- Open http://localhost:4000/authorize in your Browser
- (for refresh profiles) Click Refresh Link
- Test should pass

## How to Submit Certification

- Execute all `Relevant for Certification` profiles
- All results must be passed (green) or skipped (orange)
- Follow steps here: https://openid.net/certification/connect_rp_submission/
- All support files must be added to the `openid-foundation-certification` branch
  - To mount the branch in your worktree, call:
    `git worktree add --track -b openid-foundation-certification certification origin/openid-foundation-certification`