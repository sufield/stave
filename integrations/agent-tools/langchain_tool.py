"""LangChain tool wrapping Stave (Iteration 0.5).

    from langchain_tool import StaveVerifyTool
    agent = create_react_agent(llm, tools=[StaveVerifyTool()])

Import-guarded: usable only when `langchain-core` + `pydantic` are installed; the core
engine (`stave_verify_core`) has no such dependency.
"""
from stave_verify_core import verify, verify_text

try:
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel, Field
    _HAS_LC = True
except ImportError:  # pragma: no cover
    _HAS_LC = False


SYSTEM_PROMPT_FRAGMENT = (
    "You have access to the stave_verify tool. It performs deterministic security "
    "verification against cloud configuration snapshots. Use it BEFORE recommending or "
    "deploying any infrastructure change. If it returns findings, you MUST address them "
    "before proceeding. Stave findings are deterministic — proven violations, not "
    "suggestions. Do not override them."
)

if _HAS_LC:

    class StaveVerifyInput(BaseModel):
        snapshot_path: str = Field(..., description="Directory of obs.v0.1 snapshot JSON files.")
        pack: str = Field("", description="Optional pack to scope evaluation (e.g. 'quick', 'entropy').")
        now: str = Field("", description="Optional RFC3339 time override for deterministic runs.")

    class StaveVerifyTool(BaseTool):
        name: str = "stave_verify"
        description: str = (
            "Deterministic security verification of a cloud configuration snapshot directory. "
            "Returns proven control violations (not suggestions). Call before deploying.")
        args_schema = StaveVerifyInput

        def _run(self, snapshot_path: str, pack: str = "", now: str = "") -> str:
            return verify_text(snapshot_path, pack=pack, now=now)

        async def _arun(self, snapshot_path: str, pack: str = "", now: str = "") -> str:
            return self._run(snapshot_path, pack=pack, now=now)

    def stave_verify_structured(snapshot_path: str, **kw) -> dict:
        """Structured-output variant for agents that reason over JSON."""
        return verify(snapshot_path, **kw)

else:  # pragma: no cover

    def StaveVerifyTool(*_a, **_k):
        raise ImportError("StaveVerifyTool needs `pip install langchain-core pydantic`. "
                          "The core engine stave_verify_core.verify() works without them.")
