from fastapi import APIRouter
from vism_acme.main import VismACMEController


class OrderRouter:
    def __init__(self, controller: VismACMEController):
        self.controller = controller

        self.router = APIRouter()
        # self.router.post("/new-account")(self.new_account)
        # self.router.post("/account/{account_kid}")(self.update_account)

