"""Windows Service wrapper for OGK-Agent running as LocalSystem (`pywin32`).

Install/Start (Administrator PowerShell):
    python -m agent.src.service.windows_service install
    python -m agent.src.service.windows_service start

Console debug mode:
    python -m agent.src.service.windows_service --console
"""

from __future__ import annotations

import logging
import sys

from agent.src.config import AgentConfig
from agent.src.service.agent_core import AgentCore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

if sys.platform == "win32":
    try:
        import servicemanager  # type: ignore
        import win32event  # type: ignore
        import win32service  # type: ignore
        import win32serviceutil  # type: ignore

        class OGKAgentWindowsService(win32serviceutil.ServiceFramework):
            _svc_name_ = "OGKAgent"
            _svc_display_name_ = "OGK Companion Child Safety Agent"
            _svc_description_ = (
                "Enforces family screen-time limits, SHA-256 app rules, and local DNS safety "
                "with full transparency via the OGK Tray UI."
            )

            def __init__(self, args):
                super().__init__(args)
                self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
                self.core: AgentCore | None = None

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self.hWaitStop)
                if self.core is not None:
                    self.core.stop()

            def SvcDoRun(self):
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, ""),
                )
                cfg = AgentConfig.from_env()
                self.core = AgentCore(cfg)
                try:
                    self.core.start()
                except Exception as exc:
                    servicemanager.LogErrorMsg(f"OGKAgent fatal error: {exc}")
                    self.SvcStop()
    except ImportError:
        OGKAgentWindowsService = None  # type: ignore
else:
    OGKAgentWindowsService = None  # type: ignore


def main() -> None:
    if "--console" in sys.argv:
        cfg = AgentConfig.from_env()
        enable_watchdog = "--no-watchdog" not in sys.argv
        enable_dns = "--no-dns" not in sys.argv
        core = AgentCore(cfg, enable_dns=enable_dns, enable_tray_watchdog=enable_watchdog)
        try:
            core.start()
        except KeyboardInterrupt:
            core.stop()
        return

    if OGKAgentWindowsService is not None:
        import win32serviceutil  # type: ignore

        win32serviceutil.HandleCommandLine(OGKAgentWindowsService)
    else:
        print("pywin32 is required to run as a Windows Service. Use --console for local run.")


if __name__ == "__main__":
    main()
