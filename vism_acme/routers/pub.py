# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Router for public data requests."""

from fastapi import APIRouter
from starlette.responses import Response, HTMLResponse
from vism_acme.acme import VismACMEController


class PubRouter:
    """Router for handling ACME base endpoints like directory."""

    def __init__(self, controller: VismACMEController):
        self.controller = controller
        self.router = APIRouter()

        self.router.get("/pub")(self.pub)
        self.router.get("/pub/{object_type}")(self.pub_object_type)
        self.router.get("/pub/{object_type}/{object_name}")(self.pub_object)

    @staticmethod
    def build_index_html(paths: list[str]) -> str:
        """Build a simple HTML index listing the given files."""
        items = "\n".join(
            f'<li><a href="pub/{p}">pub/{p}</a></li>' for p in paths
        )
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
        </head>
        <body>
            <ul>
                {items}
            </ul>
        </body>
        </html>
        """

    async def pub(self):
        paths = await self.controller.s3.list_files("/")
        html = self.build_index_html(paths)
        return HTMLResponse(html)

    async def pub_object_type(self, object_type: str):
        paths = await self.controller.s3.list_files(f"{object_type.rstrip('/')}/")
        html = self.build_index_html(paths)
        return HTMLResponse(html)

    async def pub_object(self, object_type: str, object_name: str):
        object_bytes = await self.controller.s3.download_bytes(f"{object_type}/{object_name}")
        if object_bytes is None:
            return Response(status_code=404)

        return Response(content=object_bytes, status_code=200)