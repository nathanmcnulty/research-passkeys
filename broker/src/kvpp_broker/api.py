"""No-store WSGI adapter for the non-signing broker slice. No listener/deployment.

Internal worker methods are deliberately absent. A production host must enforce
HTTPS, request deadlines, quotas and reviewed/live-validated CA/device policies.
"""
from http import HTTPStatus
import json
import re

from .auth import EntraTokenVerifier
from .coordination import Coordinator
from .errors import ClaimsChallenge, Conflict, CorruptState, GateClosed, InvalidRequest, NotFound, StorageUnavailable, Unauthenticated
from .storage import strict_json

RESOURCE = re.compile(r"/v1/(credentials|reservations)/([0-9a-f]{32})(?:/(prepare|abort|finalize|sign))?\Z")


class BrokerApplication:
    def __init__(self, coordinator: Coordinator, verifier: EntraTokenVerifier):
        if coordinator.allowed_applications != verifier.config.allowed_clients:
            raise InvalidRequest("API and coordinator client policy must agree.")
        self.coordinator, self.verifier = coordinator, verifier

    def __call__(self, environ, start_response):
        status = 200
        challenge = None
        try:
            caller = self.verifier.verify(environ.get("HTTP_AUTHORIZATION", ""))
            method, path = environ.get("REQUEST_METHOD", ""), environ.get("PATH_INFO", "")
            request_key = environ.get("HTTP_IDEMPOTENCY_KEY", "")
            match = RESOURCE.fullmatch(path)
            if method == "POST" and path == "/v1/reservations":
                body = self._body(environ, {"rpId"})
                value = self.coordinator.reserve(caller, request_key, body["rpId"])
                result = {"credentialId": value["credential_id"], "state": value["state"], "expiresAt": value["expires_at"]}
                status = 201
            elif match:
                resource, identifier, action = match.groups()
                if method == "GET" and resource == "credentials" and action is None:
                    value = self.coordinator.get_credential(caller, identifier)
                    result = {"credentialId": value["credential_id"], "state": value["state"], "rpId": value["rp_id"], "counter": value["counter"]}
                elif method == "POST" and resource == "credentials" and action == "prepare":
                    body = self._body(environ, {"rpId", "clientDataHash"})
                    value = self.coordinator.prepare(caller, request_key, identifier, body["rpId"], body["clientDataHash"])
                    result = {"operationId": value["operation_id"], "counter": value["counter"], "nonce": value["nonce"], "expiresAt": value["expires_at"]}
                elif method == "POST" and resource == "reservations" and action == "abort":
                    self._body(environ, set())
                    value = self.coordinator.abort(caller, request_key, identifier)
                    result = {"credentialId": value["credential_id"], "state": value["state"]}
                elif ((method == "DELETE" and resource == "credentials" and action is None) or
                        (method == "POST" and ((resource == "credentials" and action == "sign") or
                            (resource == "reservations" and action == "finalize")))):
                    raise GateClosed("Trusted operation proof integration is required.")
                else:
                    raise NotFound()
            else:
                raise NotFound()
        except ClaimsChallenge as error:
            challenge = error.header
            status, result = 401, self._error("insufficient_claims", "Additional authentication is required.")
        except Unauthenticated:
            status, result = 401, self._error("unauthenticated", "Fresh broker authentication is required.")
        except NotFound:
            status, result = 404, self._error("not_found", "The resource was not found.")
        except InvalidRequest:
            status, result = 400, self._error("invalid_request", "The request is invalid.")
        except Conflict:
            status, result = 409, self._error("conflict", "The operation conflicts with retained state.")
        except GateClosed:
            status, result = 501, self._error("proof_integration_required", "Trusted operation proof integration is required.")
        except (StorageUnavailable, CorruptState):
            status, result = 503, self._error("storage_unavailable", "Broker storage is unavailable; preserve the request key for retry.")
        except Exception:
            status, result = 500, self._error("internal_error", "The broker could not complete this request.")
        data = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(data))),
            ("Cache-Control", "no-store"), ("Pragma", "no-cache"), ("X-Content-Type-Options", "nosniff")]
        if status == 401:
            headers.append(("WWW-Authenticate", challenge or 'Bearer error="invalid_token"'))
        start_response(f"{status} {HTTPStatus(status).phrase}", headers)
        return [data]

    @staticmethod
    def _body(environ, fields):
        if environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower() != "application/json":
            raise InvalidRequest()
        length = environ.get("CONTENT_LENGTH", "")
        if not isinstance(length, str) or not re.fullmatch(r"[0-9]{1,5}", length) or not 1 <= int(length) <= 8192:
            raise InvalidRequest()
        data = environ["wsgi.input"].read(int(length))
        if len(data) != int(length):
            raise InvalidRequest()
        try:
            value = strict_json(data.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise InvalidRequest() from exc
        if not isinstance(value, dict) or set(value) != fields:
            raise InvalidRequest()
        return value

    @staticmethod
    def _error(code, message):
        return {"error": {"code": code, "message": message}}
