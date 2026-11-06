class BrokerError(Exception):
    code = "broker_error"


class InvalidRequest(BrokerError):
    code = "invalid_request"


class NotFound(BrokerError):
    code = "not_found"


class Conflict(BrokerError):
    code = "conflict"


class Unauthenticated(BrokerError):
    code = "unauthenticated"


class ClaimsChallenge(BrokerError):
    code = "insufficient_claims"

    def __init__(self, header: str):
        super().__init__("Additional authentication is required.")
        self.header = header


class GateClosed(BrokerError):
    code = "proof_integration_required"


class StorageUnavailable(BrokerError):
    code = "storage_unavailable"


class CorruptState(BrokerError):
    code = "corrupt_state"


class CompareFailed(Exception):
    """A definitively rejected atomic transaction; safe to reread and retry."""
