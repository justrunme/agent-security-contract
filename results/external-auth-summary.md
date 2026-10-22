# External-auth integration summary

Scope: on this corpus of 12 scenarios
Passed: `True`
Critical false-ALLOW: `0`
Suite time (ms): `17327`

| Scenario | Expected | Actual | HTTP | Executed | Match |
|---|---|---|---:|---|---|
| `proxy_allow_benign_email` | ALLOW | ALLOW | 200 | True | yes |
| `proxy_allow_benign_http` | ALLOW | ALLOW | 200 | True | yes |
| `proxy_allow_benign_list` | ALLOW | ALLOW | 200 | True | yes |
| `proxy_allow_benign_read` | ALLOW | ALLOW | 200 | True | yes |
| `proxy_allow_benign_shell` | ALLOW | ALLOW | 200 | True | yes |
| `proxy_allow_benign_write` | ALLOW | ALLOW | 200 | True | yes |
| `proxy_block_exfil` | BLOCK | BLOCK | 403 | False | yes |
| `proxy_require_approval_deploy` | REQUIRE_APPROVAL | REQUIRE_APPROVAL | 401 | False | yes |
| `proxy_fail_closed_malformed` | BLOCK | BLOCK | 403 | False | yes |
| `proxy_fail_closed_no_credentials` | BLOCK | BLOCK | 401 | False | yes |
| `proxy_fail_closed_timeout` | BLOCK | BLOCK | 403 | False | yes |
| `proxy_fail_closed_authorizer_down` | BLOCK | BLOCK | 403 | False | yes |
