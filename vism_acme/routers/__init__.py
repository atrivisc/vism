from starlette.requests import Request
from starlette.datastructures import State
from vism_acme.middleware import AcmeJWSEnvelope


class AcmeRequestState(State):
    jws_envelope: AcmeJWSEnvelope

class AcmeRequest(Request):
    state: AcmeRequestState