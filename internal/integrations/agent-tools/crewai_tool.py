"""CrewAI tool wrapping Stave (Iteration 0.5).

    from crewai_tool import stave_verify_tool
    agent = Agent(role="SRE", tools=[stave_verify_tool], ...)

Import-guarded: usable only when `crewai` (or `crewai-tools`) is installed.
"""
from stave_verify_core import verify_text

try:
    from crewai.tools import tool
    _HAS_CREWAI = True
except ImportError:  # pragma: no cover
    try:
        from crewai_tools import tool
        _HAS_CREWAI = True
    except ImportError:
        _HAS_CREWAI = False

if _HAS_CREWAI:

    @tool("Stave Verify")
    def stave_verify_tool(snapshot_path: str, pack: str = "", now: str = "") -> str:
        """Deterministic security verification of a cloud config snapshot directory.
        Returns proven control violations (not suggestions). Use before deploying."""
        return verify_text(snapshot_path, pack=pack, now=now)

else:  # pragma: no cover

    def stave_verify_tool(*_a, **_k):
        raise ImportError("stave_verify_tool needs `pip install crewai`. "
                          "The core engine stave_verify_core.verify() works without it.")
