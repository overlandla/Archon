"""Trusted Theseus authority integration, using #524's canonical read component.

The separately installed/pinned adapter package supplies schema validation; this
runtime never invents handoffs, executes operation strings or reads credentials
from worker configuration. Packaging must pin this dependency with the policy.
"""
import asyncio
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .admission import Rejected


@dataclass(frozen=True)
class TheseusAuthority:
    deployment: str
    project: int
    credential: str = field(repr=False)

    def __post_init__(self):
        parsed = urlsplit(self.deployment)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443)
                or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password
                or type(self.project) is not int or self.project <= 0):
            raise ValueError("unsupported_authority_origin")

    def check(self, selection: dict) -> dict:
        from archon_adapter.context import AuthoritativeContext, StaleContextError
        from archon_adapter.coordination import SourceContext
        from archon_adapter.transport import JsonReader

        async def retrieve():
            reader = JsonReader(self.deployment, token=self.credential)
            try:
                context = AuthoritativeContext(SourceContext(self.deployment, self.project), reader)
                return await asyncio.wait_for(context.retrieve_selection(selection), timeout=60)
            except StaleContextError as error:
                raise Rejected(error.diagnostic) from None
            finally:
                await reader.close()
        # The supervisor dequeue thread owns its loop. No request/model code
        # supplies readers, transports or event-loop callbacks to this method.
        return asyncio.run(retrieve())
