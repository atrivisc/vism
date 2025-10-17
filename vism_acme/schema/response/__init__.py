from typing import Any


class ACMEProblemResponse(Exception):
    def __init__(self, type: str, title: str, detail: str = None, subproblems: list['ACMEProblemResponse'] = None, status_code: int = 400):
        self.error_json: dict[str, Any] = {
            "type": f"urn:ietf:params:acme:error:{type}",
            "title": title,
        }
        if detail is not None:
            self.error_json["detail"] = detail

        if subproblems is not None:
            self.error_json['subproblems'] = []
            for problem in subproblems:
                self.error_json['subproblems'].append(problem.error_json)

        self.status_code: int = status_code
        super().__init__(title)

