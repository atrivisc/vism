from typing import Optional, Dict, Any, Union
import aioboto3
from shared.config import S3Config
from shared.config import shared_logger

class AsyncS3Client:
    def __init__(self, config: S3Config) -> None:
        self.bucket_name = config.bucket
        self._session = aioboto3.Session(
            aws_access_key_id=config.access_key,
            aws_secret_access_key=config.secret_key,
            region_name=config.region,
        )
        self._endpoint = config.endpoint

    async def list_files(self, prefix: str) -> list[str]:
        """
        List files directly under the given prefix (non-recursive).
        Returns only objects, not "directories".

        :param prefix: e.g. "folder/" or "" for root.
        """
        async with self._session.client("s3", endpoint_url=self._endpoint) as s3:
            paginator = s3.get_paginator("list_objects_v2")

            results = []

            async for page in paginator.paginate(
                Bucket=self.bucket_name,
                Prefix=prefix,
                Delimiter="/",
            ):
                contents = page.get("Contents", [])
                for obj in contents:
                    key = obj["Key"]
                    if key != prefix:
                        results.append(key)

            return results

    async def upload_bytes(
        self,
        data: Union[bytes, bytearray, memoryview],
        key: str,
        extra_args: Optional[Dict[str, Any]] = None,
    ) -> None:
        shared_logger.info(f"Uploading file {key} to s3")
        async with self._session.client("s3", endpoint_url=self._endpoint) as s3:
            extra_args = extra_args or {}

            await s3.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=data,
                **extra_args,
            )

    async def download_bytes(self, key: str) -> Optional[bytes]:
        shared_logger.info(f"Downloading file '{key}' from s3")
        async with self._session.client("s3", endpoint_url=self._endpoint) as s3:
            try:
                resp = await s3.get_object(Bucket=self.bucket_name, Key=key)
            except Exception as e:
                shared_logger.error(f"Failed to download file '{key}' from s3: {e}")
                return None

            body = resp["Body"]
            return await body.read()

    async def exists(self, key: str) -> bool:
        async with self._session.client("s3", endpoint_url=self._endpoint) as s3:
            try:
                await s3.head_object(Bucket=self.bucket_name, Key=key)
                return True
            except s3.exceptions.NoSuchKey:
                return False
            except Exception as e:
                if getattr(e, "response", {}).get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
                    return False
                raise
