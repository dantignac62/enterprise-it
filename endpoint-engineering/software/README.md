# software

Application packaging and deployment for Intune Win32App delivery.

## What goes here

- **Per-application packaging directories** — one directory per application, containing install/uninstall scripts, detection rules, requirement rules, and a manifest describing the package.
- **Packaging pipeline scripts** — automation that wraps `IntuneWinAppUtil.exe`, calls Graph API to publish/update apps, and manages supersedence relationships.
- **Shared install helpers** — common functions for MSI/EXE installation patterns, exit code handling, and logging.

## Per-application directory layout

```
software/<app-name>/
├── manifest.json           # version, detection, requirements, assignments
├── Install.ps1             # installer wrapper with logging
├── Uninstall.ps1           # clean removal
├── Detect.ps1              # detection rule (if script-based)
├── source/                 # original installer payload (gitignored if large)
└── README.md               # vendor notes, known issues, supersedence chain
```

## Conventions

- Install/uninstall scripts log to `C:\ProgramData\EnterpriseIT\Logs\<app-name>\`.
- Exit codes follow Intune conventions: `0` = success, `1707` = success with hard reboot, `3010` = success with soft reboot, `1641` = installer initiated reboot.
- `.intunewin` artifacts are gitignored — they are build outputs, not source.
- Supersedence relationships are declared in `manifest.json` and applied by the publishing script, not by hand in the Intune portal.

## Packaging pipeline notes

Items requiring verification before each first-run against a new module version are documented in the pipeline script header — `IntuneWin32App` module parameter names, Graph API supersedence body shape, and `minimumSupportedWindowsRelease` accepted values can shift between releases.
