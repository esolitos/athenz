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

"""Tests for the GitHub Actions SIA agent."""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_csr

from sia import generate_csr, get_instance_id, get_oidc_token, parse_args, register_instance

# Test token from the Go test suite
VALID_TOKEN = (
    "eyJraWQiOiIwIiwiYWxnIjoiRVMyNTYifQ."
    "eyJleHAiOjE3MDgwMjc4MTcsImlzcyI6Imh0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2Vy"
    "Y29udGVudC5jb20iLCJhdWQiOiJodHRwczovL2F0aGVuei5pbyIsInJ1bl9pZCI6IjAwMDEiLCJl"
    "bnRlcnByaXNlIjoiYXRoZW56Iiwic3ViIjoicmVwbzphdGhlbnovc2lhOnJlZjpyZWZzL2hlYWRz"
    "L21haW4iLCJldmVudF9uYW1lIjoicHVzaCIsImlhdCI6MTcwODAyNDIxN30."
    "ykt6O1mIjIjalTrmaU9AuSSsQghZ7Mx61gDsjVPHV0-SCqYpZNy7RtEbvgjKVCZ0kJ6BijH3aEf3"
    "EGArLHjTOQ"
)


def _make_test_token(claims: dict | None = None) -> str:
    """Create a JWT token (unsigned) for testing purposes."""
    payload = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "https://athenz.io",
        "sub": "repo:athenz/sia:ref:refs/heads/main",
        "run_id": "0001",
        "repository": "athenz/sia",
        "event_name": "push",
        "enterprise": "athenz",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    if claims:
        payload.update(claims)
    return pyjwt.encode(payload, "secret", algorithm="HS256")


def _mock_oidc_response(token: str, status_code: int = 200) -> MagicMock:
    """Create a mock response object for the GitHub OIDC endpoint."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = {"value": token}
    return mock_response


# --- get_oidc_token ---


class TestGetOidcToken:
    def test_successful_token_retrieval(self, monkeypatch: pytest.MonkeyPatch):
        token = _make_test_token()
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://github.example.com/oidc?type=jwt")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-bearer-token")

        with patch("sia.requests.get", return_value=_mock_oidc_response(token)) as mock_get:
            raw, claims = get_oidc_token("https://athenz.io")

        assert raw == token
        assert claims["run_id"] == "0001"
        assert claims["repository"] == "athenz/sia"
        assert claims["event_name"] == "push"
        assert claims["enterprise"] == "athenz"

        # verify request was made correctly
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args
        assert "audience=https://athenz.io" in call_kwargs[0][0]
        assert call_kwargs[1]["headers"]["Authorization"] == "Bearer test-bearer-token"
        assert call_kwargs[1]["headers"]["User-Agent"] == "actions/oidc-client"

    def test_with_go_test_token(self, monkeypatch: pytest.MonkeyPatch):
        """Use the exact token from the Go test suite."""
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://github.example.com/oidc?type=jwt")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

        with patch("sia.requests.get", return_value=_mock_oidc_response(VALID_TOKEN)):
            raw, claims = get_oidc_token("https://athenz.io")

        assert raw == VALID_TOKEN
        assert claims["run_id"] == "0001"
        assert claims["enterprise"] == "athenz"

    def test_missing_request_url(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
        monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)

        with pytest.raises(RuntimeError, match="ACTIONS_ID_TOKEN_REQUEST_URL environment variable not set"):
            get_oidc_token("https://athenz.io")

    def test_missing_request_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://github.example.com/oidc?type=jwt")
        monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)

        with pytest.raises(RuntimeError, match="ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not set"):
            get_oidc_token("https://athenz.io")

    def test_http_error_status(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://github.example.com/oidc?type=jwt")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

        with patch("sia.requests.get", return_value=_mock_oidc_response("", status_code=400)):
            with pytest.raises(RuntimeError, match="OIDC token get status error: 400"):
                get_oidc_token("https://athenz.io")

    def test_invalid_token_format(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://github.example.com/oidc?type=jwt")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

        with patch("sia.requests.get", return_value=_mock_oidc_response("not-a-jwt")):
            with pytest.raises(RuntimeError, match="Unable to parse OIDC token"):
                get_oidc_token("https://athenz.io")

    def test_http_request_exception(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://github.example.com/oidc?type=jwt")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

        import requests as req
        with patch("sia.requests.get", side_effect=req.ConnectionError("connection refused")):
            with pytest.raises(RuntimeError, match="Unable to execute HTTP GET request"):
                get_oidc_token("https://athenz.io")


# --- get_instance_id ---


class TestGetInstanceId:
    def test_valid_claims(self):
        claims = {"repository": "athenz/sia", "run_id": "0001"}
        assert get_instance_id(claims) == "athenz:sia:0001"

    def test_repository_with_org(self):
        claims = {"repository": "my-org/my-repo", "run_id": "42"}
        assert get_instance_id(claims) == "my-org:my-repo:42"

    @pytest.mark.parametrize("missing_field", ["repository", "run_id"])
    def test_missing_field(self, missing_field: str):
        claims = {"repository": "athenz/sia", "run_id": "0001"}
        del claims[missing_field]

        with pytest.raises(RuntimeError, match=missing_field):
            get_instance_id(claims)

    def test_empty_field(self):
        claims = {"repository": "", "run_id": "0001"}
        with pytest.raises(RuntimeError, match="repository"):
            get_instance_id(claims)


# --- generate_csr ---


class TestGenerateCsr:
    @pytest.fixture()
    def private_key(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_basic_csr(self, private_key):
        csr_pem = generate_csr(
            private_key, "sports", "api", "sys.auth.github-actions",
            "athenz:sia:0001", "athenz.io",
        )
        assert "BEGIN CERTIFICATE REQUEST" in csr_pem

        csr = load_pem_x509_csr(csr_pem.encode())
        assert csr.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value == "sports.api"

        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "api.sports.athenz.io" in dns_names

        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert "athenz://instanceid/sys.auth.github-actions/athenz:sia:0001" in uris

    def test_csr_with_spiffe(self, private_key):
        csr_pem = generate_csr(
            private_key, "sports", "api", "sys.auth.github-actions",
            "athenz:sia:0001", "athenz.io",
            spiffe_trust_domain="athenz",
        )

        csr = load_pem_x509_csr(csr_pem.encode())
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert "spiffe://athenz/ns/default/sa/sports.api" in uris
        assert "athenz://instanceid/sys.auth.github-actions/athenz:sia:0001" in uris

    def test_csr_subject_fields(self, private_key):
        csr_pem = generate_csr(
            private_key, "sports", "api", "sys.auth.github-actions",
            "id", "athenz.io",
            subj_c="DE", subj_o="MyOrg", subj_ou="MyUnit",
        )

        csr = load_pem_x509_csr(csr_pem.encode())
        subject = csr.subject
        assert subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value == "DE"
        assert subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value == "MyOrg"
        assert subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "MyUnit"


# --- register_instance ---


class TestRegisterInstance:
    def test_successful_registration(self):
        response_data = {
            "x509Certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            "x509CertificateSigner": "-----BEGIN CERTIFICATE-----\nsigner\n-----END CERTIFICATE-----",
        }

        with patch("sia.requests.post") as mock_post:
            mock_post.return_value.status_code = 201
            mock_post.return_value.json.return_value = response_data

            result = register_instance(
                "https://zts.athenz.io/zts/v1",
                "sys.auth.github-actions", "sports", "api",
                "oidc-token", "csr-pem", 360,
            )

        assert result["x509Certificate"] == response_data["x509Certificate"]
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs[0][0] == "https://zts.athenz.io/zts/v1/instance"
        assert call_kwargs[1]["json"]["provider"] == "sys.auth.github-actions"
        assert call_kwargs[1]["json"]["attestationData"] == "oidc-token"
        assert "token" not in call_kwargs[1]["json"]

    def test_registration_with_oidc_token(self):
        response_data = {
            "x509Certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            "serviceToken": "oidc-service-token",
        }

        with patch("sia.requests.post") as mock_post:
            mock_post.return_value.status_code = 201
            mock_post.return_value.json.return_value = response_data

            result = register_instance(
                "https://zts.athenz.io/zts/v1",
                "sys.auth.github-actions", "sports", "api",
                "oidc-token", "csr-pem", 360,
                get_oidc_token_flag=True,
                oidc_token_audience="my-audience",
                oidc_key_type="EC",
            )

        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"]
        assert payload["token"] is True
        assert payload["jwtSVIDAudience"] == "my-audience"
        assert payload["jwtSVIDKeyType"] == "EC"
        assert result["serviceToken"] == "oidc-service-token"

    def test_failed_registration(self):
        with patch("sia.requests.post") as mock_post:
            mock_post.return_value.status_code = 403
            mock_post.return_value.text = "Forbidden"

            with pytest.raises(RuntimeError, match="Unable to register instance: 403"):
                register_instance(
                    "https://zts.athenz.io/zts/v1",
                    "sys.auth.github-actions", "sports", "api",
                    "oidc-token", "csr-pem", 360,
                )

    def test_with_ca_cert(self):
        with patch("sia.requests.post") as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"x509Certificate": "cert"}

            register_instance(
                "https://zts.athenz.io/zts/v1",
                "sys.auth.github-actions", "sports", "api",
                "token", "csr", 360, ca_cert="/path/to/ca.pem",
            )

        assert mock_post.call_args[1]["verify"] == "/path/to/ca.pem"

    def test_url_trailing_slash_stripped(self):
        with patch("sia.requests.post") as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"x509Certificate": "cert"}

            register_instance(
                "https://zts.athenz.io/zts/v1/",
                "sys.auth.github-actions", "sports", "api",
                "token", "csr", 360,
            )

        assert mock_post.call_args[0][0] == "https://zts.athenz.io/zts/v1/instance"


# --- parse_args ---


class TestParseArgs:
    def test_required_args(self):
        opts = parse_args([
            "--key-file", "/tmp/key", "--cert-file", "/tmp/cert",
            "--domain", "sports", "--service", "api",
            "--zts", "https://zts.athenz.io", "--dns-domain", "athenz.io",
        ])
        assert opts.domain == "sports"
        assert opts.provider == "sys.auth.github-actions"
        assert opts.expiry_time == 360

    def test_defaults(self):
        opts = parse_args([
            "--key-file", "k", "--cert-file", "c",
            "--domain", "d", "--service", "s",
            "--zts", "z", "--dns-domain", "dns",
        ])
        assert opts.subj_c == "US"
        assert opts.subj_ou == "Athenz"
        assert opts.provider == "sys.auth.github-actions"
        assert opts.cacert == ""
        assert opts.spiffe_trust_domain == ""
        assert opts.get_oidc_token is False
        assert opts.oidc_token_audience == ""
        assert opts.oidc_key_type == "EC"

    def test_get_oidc_token_flag(self):
        opts = parse_args([
            "--key-file", "k", "--cert-file", "c",
            "--domain", "d", "--service", "s",
            "--zts", "z", "--dns-domain", "dns",
            "--get-oidc-token",
            "--oidc-token-audience", "my-audience",
            "--oidc-key-type", "RSA",
        ])
        assert opts.get_oidc_token is True
        assert opts.oidc_token_audience == "my-audience"
        assert opts.oidc_key_type == "RSA"
