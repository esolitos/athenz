# SIA for GitHub Actions

The SIA utility authenticates GitHub Actions workflow runs with Athenz and
obtains a service identity X.509 certificate.

The OIDC token is retrieved from the GitHub Actions OIDC endpoint using the
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` environment
variables, which are automatically provided by GitHub when the workflow has
`id-token: write` permission.

## Dependencies

The script requires Python 3.10+ and the following packages:

- `cryptography>=43.0`
- `PyJWT>=2.9`
- `requests>=2.32`

When [uv](https://docs.astral.sh/uv/) is available, dependencies are resolved
automatically. Otherwise, install them with `pip install cryptography PyJWT requests`.

## Usage

```
./sia.py --zts <zts-server-url> --domain <athenz-domain> --service <athenz-service> \
         --dns-domain <dns-domain> --key-file <key-file> --cert-file <cert-file>
```

To also obtain an OIDC token from ZTS (written to `$GITHUB_ENV`):

```
./sia.py --zts <zts-server-url> --domain <athenz-domain> --service <athenz-service> \
         --dns-domain <dns-domain> --key-file <key-file> --cert-file <cert-file> \
         --get-oidc-token --oidc-token-audience <audience> --oidc-key-type EC
```

The utility will generate a unique RSA private key and obtain a service identity
X.509 certificate from Athenz and store the key and certificate in the specified files.

As part of its output, the agent shows the action and resource values that the domain
administrator must use to configure the Athenz services to allow the GitHub Actions
workflow to authorize:

```
2024/02/15 17:05:43 Action: github.push
2024/02/15 17:05:43 Resource: sports:repo:athenz/sia:ref:refs/heads/main
```

## Testing

```
python3 -m pytest -v sia_test.py
```
