from starlette.requests import Request
from starlette.datastructures import State
from vism_acme.db import AccountEntity
from vism_acme.middleware.jwt import AcmeJWSEnvelope


class AcmeRequestState(State):
    jws_envelope: AcmeJWSEnvelope
    account: AccountEntity

class AcmeRequest(Request):
    state: AcmeRequestState