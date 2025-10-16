from starlette.responses import JSONResponse


class ACMEProblemResponse(Exception):
    def __init__(self, type: str, title: str, detail: str = None, status_code: int = 400):
        error_json = {
            "type": f"urn:ietf:params:acme:error:{type}",
            "title": title,
        }
        if detail is not None:
            error_json["detail"] = detail

        self.error_json = error_json
        self.status_code = status_code
        super().__init__(title)

