# AutoMap 2.5.1 Validation

## Recorded VM Result

The user's 2026-09-28 17:32 run used Windows PowerShell 5.1 in a non-elevated session. AutoMap loaded one credential, connected the configured NAS share on its first attempt through explicit net use, verified drive access, and completed with one success and no failures or warnings in the text log (approximately 15 seconds). This validates the tested setup, not every server, policy, or Windows configuration. The following procedure remains useful for future regression testing.

## Why This Patch

An Explorer drive letter is not evidence of an authenticated, usable connection. Earlier AutoMap code accepted a matching `net use` entry as success, and incremented the success count even when access verification failed. It also removed unavailable mappings before checking its SMB repair path and could silently fall back to the sign-in identity when a configured password could not be loaded.

The 2.5.1 candidate uses explicit persistent `net use` after successfully preparing the bare-server credential. If preparation fails, it attempts native credential saving through `New-SmbMapping` when supported, with explicit `net use` as the fallback. Neither registering a drive nor saving a password alone counts as verified drive access.

The first VM test of 2.5.1 aborted at the inherited network preflight before loading credentials. The updated candidate removes that gate: no physical-adapter, IPv4, or public-Internet ping requirement precedes SMB mapping. The log should now say `Checking configured shares directly`, followed by credential loading and mapping results. Missing/malformed configuration and failed mappings return a nonzero exit code.

## Fresh-VM Acceptance Test

1. Use a Windows 10/11 VM snapshot or fresh Windows account that has never connected to the test share through Explorer. Do not copy another Windows user's DPAPI credential file into it.
2. Run this checkout's `Share_Manager.ps1` as that user, without administrator rights. Configure the share, save its credentials inside Share Manager, and enable persistent mapping. Do not establish an Explorer mapping first.
3. Confirm `%APPDATA%\Share_Manager\Share_Manager_AutoMap.ps1` starts with version `2.5.1`. The application regenerates this file during normal startup with persistent mapping enabled.
4. Sign out and sign in, or reboot. Wait for AutoMap to finish, then open the drive in Explorer without running Share Manager's manual Connect action. It must open without requesting credentials.
5. Inspect `%APPDATA%\Share_Manager\LogonScript.log` and `LogonScript.events.jsonl`. Verify version `2.5.1`, Windows PowerShell, a non-elevated execution context, the chosen backend, and an access-verified result. `credentialsSavedBySmb: false` means the SMB save path was not successful or unavailable; it does not prove that Credential Manager is empty.
6. Repeat sign-in, then test a server password change and a server that becomes reachable late. These are separate scenarios; retain the logs if either fails.

If it still shows a red X, preserve the latest AutoMap log before manually connecting. The backend/save error and authentication error are needed to separate script defects from server or Windows-policy failures. Do not disable Credential Guard, SMB signing, or other authentication protections to make the test pass.

## Evidence and Limits

DEBUG messages are retained only in `LogonScript.events.jsonl`; the text log contains progress and actionable warnings/errors. Final acceptance should use regenerated startup files from the latest candidate, since all development iterations share version 2.5.1.

The VM subsequently verified drive access through explicit `net use`, while native mapping returned a generic CIM "parameter is incorrect" exception. AutoMap now selects `net use` directly when bare-server credential preparation succeeds; native credential saving remains a fallback when preparation fails. This avoids the failing call in the observed case rather than suppressing its warning, and does not claim to identify the rejected native parameter. Microsoft documents [cmdkey credential storage](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) and [net use explicit credentials and persistence](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/gg651155(v=ws.11)).

The startup workflow runs non-elevated with a session-local mutex. It reconnects matching mappings in place first, with three attempts separated by 30-second waits and individually bounded mapping/access checks. This is a finite sign-in recovery window, not an ongoing VPN monitor. Networks becoming reachable after it finishes require another run.

Recognized authentication and session-conflict errors stop retries. A necessary stale-mapping reset preserves the remembered profile and refuses to force-close open files. Occupied letters and other targets are left alone. Missing configured credentials never silently switch to the sign-in identity.

Run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Debug\test_automap.ps1` for isolated generated-script process tests and real CMD launcher success/failure tests with special-character paths.

The host examined during development had prior manual connections. Its most recent captured sign-in ran AutoMap 2.4.0 under PowerShell 7 and reported credentials loaded and mapping success. That is not a reproduction of the fresh-VM issue, and the old success message did not establish access. Automated tests use synthetic credentials and mocked Windows boundaries; they cannot prove Explorer reconnect behavior across sign-in.

Microsoft references:

- [New-SmbMapping: Persistent and SaveCredentials are separate options](https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbmapping)
- [Mapped drives and elevated versus non-elevated logon contexts](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command)
- [Credential Guard considerations](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues)
- [Microsoft's historical reconnect example](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-network-drive-fail-reconnect): non-elevated execution with three attempts and 30-second waits. This article addresses Windows 10 version 1809, not proof of the cause on this VM.
- [WNetCancelConnection2W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetcancelconnection2w): flags zero preserves the remembered profile; force false protects open files.

These documents explain relevant Windows behavior; they do not establish Credential Guard as the cause of this VM's failure.
