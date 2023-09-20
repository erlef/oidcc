# Openid Foundation Certification

This branch contains support materials for the certification.

## Files

* `/[VERSION]/[PROFILE]/PLAN.txt` - Public Link to Test Plan
* `/[VERSION]/[PROFILE]/[TEST_NAME].png` - Screenshot of token response / error
* `/[VERSION]/[PROFILE]/Certification of Conformance.pdf` - Certification PDF
* `/submitted_certifications/Erlang_Ecosystem_Foundation-oidcc-[PROFILE]-[DATE].zip`
  - Submitted Certification Archive

All `.png` files should be compressed using a tool like
[`optipng`](https://optipng.sourceforge.net/).

## Conformance Testing

### Setup

- Register on https://www.certification.openid.net/
- Create Testplan https://www.certification.openid.net/schedule-test.html

### Conformance Profiles to Test

#### OpenID Connect Core: Basic Certification Profile Relying Party Tests

- **Relevant for Certification: Yes**
- Id: `oidcc-client-basic-certification-test-plan`
- Request Type: `plain_http_request`
- Client Registration Type: `dynamic_client`

#### OpenID Connect Core Client Tests: Comprehensive client test

- **Relevant for Certification: No**
- Expected Failures
  - `oidcc-client-test-discovery-webfinger-acct` - WebFinger is not supported
  - `oidcc-client-test-discovery-webfinger-url` - Webfinger is not supported
- Id: `oidcc-client-test-plan`
- Client Authentication Type: `client_secret_post`
- Request Type: `plain_http_request`
- Response Type: `code`
- Client Registration Type: `dynamic_client`
- Response Mode: `default`

#### OpenID Connect Core Client Refresh Token Profile Tests: Relying party refresh token tests

- **Relevant for Certification: No**
- Id: `oidcc-client-refreshtoken-test-plan`
- Client Authentication Type: `client_secret_basic`
- Request Type: `plain_http_request`
- Response Type: `code`
- Client Registration Type: `dynamic_client`
- Response Mode: `form_post`

#### OpenID Connect Core: Form Post Basic Certification Profile Relying Party Tests

- **Relevant for Certification: Yes**
- Id: `oidcc-client-formpost-basic-certification-test-plan`
- Request Type: `plain_http_request`
- Client Registration Type: `dynamic_client`

#### OpenID Connect Core: Configuration Certification Profile Relying Party Tests

- **Relevant for Certification: Yes**
- Id: `oidcc-client-config-certification-test-plan`
- Client Authentication Type: `client_secret_basic`
- Request Type: `plain_http_request`
- Response Mode: `default`
- Client Registration Type: `dynamic_client`

#### OpenID Connect Core Client Login Tests: Relying party 3rd party initiated login tests

- **Relevant for Certification: Yes**
- Id: `oidcc-client-test-3rd-party-init-login-test-plan`
- Client Authentication Type: `client_secret_basic`
- Request Type: `plain_http_request`
- Response Mode: `default`
- Client Registration Type: `dynamic_client`

## How to Execute the tests

### Setup

```console
mix deps.get
```

### Run

- Open Plan / Specific Test
- Execute the Conformance runner:
  ```console
  mix run_certification \
    --profile [PROFILE_NAME] \
    --test-name [TEST_NAME] \
    --alias [ALIAS] \ # Alias in www.certification.openid.net; Default "test"
    --version [VERSION] \ # Version to file Result artifacts for; Default "dev"
    --[no-]register-client \ # Run Client Registration; Default true; Disable for config only tests
    --[no-]start-server \ # Run Web Server; Default true; Disable for config / client only tests
    --[no-]auto-stop \ # Auto Stop when result is received; Default true; Disable for tests with multiple actions
    --[no-]auto-open \ # Auto open browser; Default false; Requires `xdg-open`
    --[no-]auto-screenshot # Auto screenshot window; Default false; Requires `gnome-screenshot` & `optipng`
  ```
- Open http://localhost:4000/authorize in your Browser (or `auto-open`)
- Follow Test Protocol
- Test should pass
- Upload Screenshot to Test Protocol

## How to Submit Certification

- Execute all `Relevant for Certification` profiles
- All results must be passed (green) or skipped (orange)
- Follow steps here: https://openid.net/certification/connect_rp_submission/
- All support files must be added to the `openid-foundation-certification` branch
  - To mount the branch in your worktree, call:
    `git worktree add --track -b openid-foundation-certification certification origin/openid-foundation-certification`
