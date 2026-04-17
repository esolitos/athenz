#!/bin/sh
''':'
if command -v uv >/dev/null 2>&1; then
  exec uv run --script "$0" "$@"
else
  exec python3 "$0" "$@"
fi
':'''
# /// script
# dependencies = [
#   "cryptography>=43.0",
#   "PyJWT>=2.9",
#   "requests>=2.32",
# ]
# ///
from __future__ import annotations
#
# Copyright The Athenz Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Service Identity Agent for GitHub Actions.

Obtains an Athenz X.509 service identity certificate using a GitHub Actions
OIDC token. The token is retrieved from the GitHub Actions OIDC endpoint using
the ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN environment
variables.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

VERSION = "development"

JWT_ALGORITHMS = [
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "EdDSA",
]

log = logging.getLogger("sia-github-actions")


def get_oidc_token(zts_url: str) -> tuple[str, dict[str, Any]]:
    """Retrieve GitHub Actions OIDC token from the GitHub OIDC endpoint.

    The token is obtained by making an HTTP GET request to the URL specified
    in ACTIONS_ID_TOKEN_REQUEST_URL, authenticated with the bearer token from
    ACTIONS_ID_TOKEN_REQUEST_TOKEN.

    Returns:
        Tuple of (raw_token, claims_dict).

    Raises:
        RuntimeError: If the token cannot be obtained or parsed.
    """
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "").strip()
    if not request_url:
        raise RuntimeError(
            "ACTIONS_ID_TOKEN_REQUEST_URL environment variable not set"
        )

    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "").strip()
    if not request_token:
        raise RuntimeError(
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not set"
        )

    github_url = f"{request_url}&audience={zts_url}"
    try:
        response = requests.get(
            github_url,
            headers={
                "User-Agent": "actions/oidc-client",
                "Authorization": f"Bearer {request_token}",
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Unable to execute HTTP GET request: {exc}") from exc

    if response.status_code != 200:
        raise RuntimeError(
            f"OIDC token get status error: {response.status_code}"
        )

    try:
        json_data = response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"Unable to parse OIDC token response: {exc}"
        ) from exc

    oidc_token = json_data.get("value", "")
    if not oidc_token:
        raise RuntimeError("OIDC token response missing 'value' field")

    try:
        claims: dict[str, Any] = jwt.decode(
            oidc_token,
            options={"verify_signature": False},
            algorithms=JWT_ALGORITHMS,
        )
    except jwt.exceptions.DecodeError as exc:
        raise RuntimeError(f"Unable to parse OIDC token: {exc}") from exc

    return oidc_token, claims


def get_instance_id(claims: dict[str, Any]) -> str:
    """Construct instance ID from token claims.

    Format: <org>:<repo>:<run_id>

    The repository claim is in 'org/repo' format; the '/' is replaced with ':'.

    Raises:
        RuntimeError: If required claims are missing.
    """
    missing = [
        field for field in ("repository", "run_id")
        if not claims.get(field)
    ]
    if missing:
        raise RuntimeError(
            f"Unable to extract {', '.join(missing)} from OIDC token claims"
        )

    repository = claims["repository"].replace("/", ":")
    return f"{repository}:{claims['run_id']}"


def generate_csr(
    private_key: rsa.RSAPrivateKey,
    domain: str,
    service: str,
    provider: str,
    instance_id: str,
    dns_domain: str,
    spiffe_trust_domain: str = "",
    subj_c: str = "US",
    subj_o: str = "",
    subj_ou: str = "Athenz",
) -> str:
    """Generate a PEM-encoded X.509 CSR with Athenz SAN entries.

    Returns:
        PEM-encoded CSR as a string.
    """
    # build subject name attributes
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, f"{domain}.{service}")]
    if subj_c:
        name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subj_c))
    if subj_o:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subj_o))
    if subj_ou:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subj_ou))

    # build SAN entries
    san_entries: list[x509.GeneralName] = []

    # SAN DNS: <service>.<domain>.<dns_domain>
    san_entries.append(x509.DNSName(f"{service}.{domain}.{dns_domain}"))

    # SPIFFE URI must be first URI entry
    if spiffe_trust_domain:
        spiffe_uri = f"spiffe://{spiffe_trust_domain}/ns/default/sa/{domain}.{service}"
        san_entries.append(x509.UniformResourceIdentifier(spiffe_uri))

    # instance ID URI
    instance_uri = f"athenz://instanceid/{provider}/{instance_id}"
    san_entries.append(x509.UniformResourceIdentifier(instance_uri))

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(name_attrs))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    return csr.public_bytes(serialization.Encoding.PEM).decode()


def register_instance(
    zts_url: str,
    provider: str,
    domain: str,
    service: str,
    attestation_data: str,
    csr: str,
    expiry_time: int,
    ca_cert: str | None = None,
    get_oidc_token_flag: bool = False,
    oidc_token_audience: str = "",
    oidc_key_type: str = "EC",
) -> dict[str, Any]:
    """Register instance with ZTS and obtain X.509 certificate.

    Returns:
        Response dict with x509Certificate, x509CertificateSigner, and
        optionally serviceToken.

    Raises:
        RuntimeError: If the registration request fails.
    """
    url = f"{zts_url.rstrip('/')}/instance"
    payload: dict[str, Any] = {
        "provider": provider,
        "domain": domain,
        "service": service,
        "attestationData": attestation_data,
        "csr": csr,
        "expiryTime": expiry_time,
    }

    if get_oidc_token_flag:
        payload["token"] = True
        payload["jwtSVIDAudience"] = oidc_token_audience
        payload["jwtSVIDKeyType"] = oidc_key_type

    verify: bool | str = ca_cert if ca_cert else True
    response = requests.post(
        url,
        json=payload,
        headers={"User-Agent": f"SIA-GitHub-Actions {VERSION}"},
        verify=verify,
        timeout=30,
    )

    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Unable to register instance: {response.status_code} {response.text}"
        )

    return response.json()


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GitHub Actions Service Identity Agent for Athenz",
    )
    parser.add_argument("--key-file", required=True, help="output private key file")
    parser.add_argument("--cert-file", required=True, help="output certificate file")
    parser.add_argument("--signer-cert-file", default="", help="output signer certificate file (optional)")
    parser.add_argument("--domain", required=True, help="domain of service")
    parser.add_argument("--service", required=True, help="name of service")
    parser.add_argument("--zts", required=True, help="url of the ZTS Service")
    parser.add_argument("--dns-domain", required=True, help="dns domain suffix for sanDNS entries")
    parser.add_argument("--subj-c", default="US", help="Subject C/Country field (default: US)")
    parser.add_argument("--subj-o", default="", help="Subject O/Organization field (optional)")
    parser.add_argument("--subj-ou", default="Athenz", help="Subject OU/OrganizationalUnit field (default: Athenz)")
    parser.add_argument("--provider", default="sys.auth.github-actions", help="Athenz Provider (default: sys.auth.github-actions)")
    parser.add_argument("--cacert", default="", help="CA certificate file (optional)")
    parser.add_argument("--spiffe-trust-domain", default="", help="SPIFFE trust domain (optional)")
    parser.add_argument("--expiry-time", type=int, default=360, help="expiry time in minutes (default: 360)")
    parser.add_argument("--get-oidc-token", action="store_true", help="Get OIDC token from Athenz ZTS along with X.509 identity certificate")
    parser.add_argument("--oidc-token-audience", default="", help="OIDC token audience (optional)")
    parser.add_argument("--oidc-key-type", default="EC", help="OIDC token signing key type: RSA/EC (default: EC)")
    parser.add_argument("--version", action="store_true", help="Show version")
    return parser.parse_args(args)


def main(args: list[str] | None = None) -> None:
    logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)

    opts = parse_args(args)

    if opts.version:
        log.info("SIA GitHub-Actions version: %s", VERSION)
        sys.exit(0)

    # get the OIDC token from GitHub Actions
    token, claims = get_oidc_token(opts.zts)

    # construct the instance id from the claims
    instance_id = get_instance_id(claims)

    # display the action and resource for athenz policy configuration
    event_name = claims.get("event_name", "")
    subject = claims.get("sub", "")
    if not subject:
        log.fatal("Unable to extract subject from OIDC token claims")
        sys.exit(1)

    log.info("Action: %s", f"github.{event_name}")
    log.info("Resource: %s", f"{opts.domain}:{subject}")

    # generate RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # generate CSR
    csr = generate_csr(
        private_key,
        opts.domain,
        opts.service,
        opts.provider,
        instance_id,
        opts.dns_domain,
        opts.spiffe_trust_domain,
        opts.subj_c,
        opts.subj_o,
        opts.subj_ou,
    )

    # register with ZTS
    identity = register_instance(
        opts.zts,
        opts.provider,
        opts.domain,
        opts.service,
        token,
        csr,
        opts.expiry_time,
        opts.cacert or None,
        opts.get_oidc_token,
        opts.oidc_token_audience,
        opts.oidc_key_type,
    )

    # write private key
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = Path(opts.key_file)
    key_path.write_bytes(key_pem)
    key_path.chmod(0o400)

    # write certificate
    cert_path = Path(opts.cert_file)
    cert_path.write_text(identity["x509Certificate"])
    cert_path.chmod(0o444)

    # write signer certificate if requested
    if opts.signer_cert_file and identity.get("x509CertificateSigner"):
        signer_path = Path(opts.signer_cert_file)
        signer_path.write_text(identity["x509CertificateSigner"])
        signer_path.chmod(0o444)

    # write OIDC token to GITHUB_ENV if requested
    if opts.get_oidc_token:
        service_token = identity.get("serviceToken", "")
        if not service_token:
            log.fatal("OIDC Token not found in identity response")
            sys.exit(1)

        github_env = os.environ.get("GITHUB_ENV", "")
        if not github_env:
            log.info(
                "GITHUB_ENV environment variable is not set. "
                "Skipping setting OIDC token in environment."
            )
            return

        with open(github_env, "a") as f:
            f.write(f"ZTS_OIDC_TOKEN={service_token}\n")


if __name__ == "__main__":
    main()
