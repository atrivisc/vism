from starlette.requests import Request
from starlette.datastructures import State
from vism_acme.db import AccountEntry
from vism_acme.middleware.jwt import AcmeJWSEnvelope


class AcmeRequestState(State):
    jws_envelope: AcmeJWSEnvelope
    account: AccountEntry

class AcmeRequest(Request):
    state: AcmeRequestState