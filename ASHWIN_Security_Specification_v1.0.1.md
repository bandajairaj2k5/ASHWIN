# ASHWIN — Security & Architecture Specification

| Field | Value |
|---|---|
| Document ID | ASHWIN-SPEC |
| Version | **1.0.1** |
| Revision date | **2026-09-30** |
| Status | **AUTHORITATIVE — FROZEN** |
| Scope | ASHWIN V1: phone core, AI Router, Moto storage endpoint, Windows laptop endpoint, online connectors, voice |

---

# 1. DOCUMENT CONTROL

## 1.1 Authority

This is the only authoritative ASHWIN specification. There are no supplementary or "supersedes" documents. If any other document, chat message, or earlier draft conflicts with this file, this file wins.

Where this specification does not define a behavior, the fail-closed principle (Section 14) applies.

## 1.2 Change control

- Any change requires a new full version of this file with a new version number and revision date.
- Corrections must not be issued as separate patch documents.
- Requirement IDs of the form `RULE-nn` and test IDs of the form `T-nn` are stable identifiers.
- Each `RULE-nn` is defined exactly once, at the place marked `[RULE-nn]`. Other sections refer to it by ID only.

## 1.3 Obsolete / non-authoritative drafts

All of the following are **obsolete and non-authoritative**. They must not be used to build, review, or test ASHWIN.

| ID | Draft | Status |
|---|---|---|
| D1 | "ASHWIN — COMPLETE PROJECT CONCEPT" | Obsolete. Non-security product baseline carried into Section 2. |
| D2 | "Corrected Windows laptop architecture" (unnamed) | Obsolete |
| D3 | "ASHWIN — ARCHITECTURE CORRECTIONS" | Obsolete |
| D4 | "ASHWIN — WINDOWS ENDPOINT SECURITY REVISION" | Obsolete |
| D5 | "ASHWIN — AUTHORITATIVE LAPTOP + STORAGE SECURITY SPECIFICATION" | Obsolete |
| D6 | "ASHWIN — AUTHORITATIVE ENDPOINT SECURITY REVISION V2" | Obsolete |
| D7 | "ASHWIN — AUTHORITATIVE PRIVACY + ENDPOINT SECURITY REVISION" | Obsolete |
| D8 | "ASHWIN — FINAL CONSOLIDATED SECURITY SPECIFICATION" | Obsolete |
| D9 | "ASHWIN — FINAL CORRECTIONS TO LAPTOP ENDPOINT" | Obsolete |
| D10 | "ASHWIN — SECURITY AND CONNECTOR CORRECTIONS" | Obsolete |
| D11 | "ASHWIN — FILE-VIEWING, IDENTIFIER, AND SECRET-HANDLING CORRECTIONS" | Obsolete |
| D12 | All later numbered correction instructions given in chat | Obsolete (merged here) |
| D13 | `ASHWIN_Security_Specification_v1.0.0.md` | Obsolete. Replaced in full by v1.0.1 |

## 1.4 Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-09-30 | First consolidated release |
| 1.0.1 | 2026-09-30 | Resolves O-1 to O-4 and the Moto pipeline ordering. Adds RULE-14 (metadata pipeline) and RULE-15 (file locations), assigns `read_document_text` to Class C, binds `folder_id` identity, corrects the Moto pipeline, and adds tests T-53 to T-57. No other rule, test, limit, classification, or routing policy changed |

---

# 2. ARCHITECTURE AND PRODUCT BASELINE

## 2.1 Roles

```text
                    USER
                      │  voice / text
                      ▼
            ┌───────────────────┐
            │ NEW ANDROID PHONE │
            │      ASHWIN       │
            │ Core · AI Router  │
            │ Memory · Perms    │
            │ Tools · Security  │
            │ Voice · Audit     │
            └─────────┬─────────┘
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       MOTO G3     LAPTOP      ONLINE
       storage     restricted  services
       server      endpoint    (connectors)
```

- **New Android phone:** hosts ASHWIN Core: AI Router, memory, permissions, tool manager, security policy, voice interface, audit log, connector management.
- **Moto G3:** private external storage server. It is not ASHWIN's brain, control plane, laptop controller, or remote shell.
- **Windows laptop:** restricted endpoint. It is not a remote shell.
- **Online services:** Gmail, Calendar, GitHub, LinkedIn, portfolio, web search, job search, reminders, notifications. Each is a separate connector.

## 2.2 Intelligence versus authority

- The AI model is a replaceable reasoning engine. It proposes actions.
- ASHWIN Core owns identity, memory, permissions, tools, devices, connections, security, and action execution.
- Only authorized ASHWIN tools perform actions. The AI has no raw access to any device or service.
- A capability that has no tool cannot be invoked through ASHWIN.

## 2.3 AI Router (product baseline)

- Model-agnostic: local AI, free cloud AI, paid cloud AI, and future models plug into the same interface.
- Graceful fallback between providers is allowed, but fallback never overrides classification, routing, or consent rules (Sections 4 and 5).
- ASHWIN itself has no mandatory recurring subscription. A local model is the permanent fallback where practical. Free cloud tiers are not assumed permanent.

## 2.4 Storage independence

- If the Moto is offline or disconnected, ASHWIN continues to function. Only storage-dependent operations fail.
- Storage access goes through a `StorageConnector` interface so the Moto can be replaced without changing ASHWIN Core.
- Storage domains are separate: PHONE (ASHWIN's own data; personal files need Android permissions or user selection), MOTO, LAPTOP. None implies access to another.

## 2.5 Honesty

ASHWIN never claims an action happened when it did not, and never fabricates a result. Examples:

- Moto offline → "Your private storage server is currently unavailable."
- Failed GitHub push → "The GitHub update failed. The repository was not changed."

## 2.6 Memory separation

Four kinds of information stay separate: conversation context (temporary), long-term memory (intentionally retained), configuration, and credentials. Credentials are never stored in normal AI memory.

## 2.7 Voice baseline

- Pipeline: microphone → speech-to-text → ASHWIN Core → AI Router → reasoning → text response → text-to-speech.
- Push-to-talk first. Always-listening wake word may be added later.
- Voice character: deep, calm, synthetic, intelligent, controlled, futuristic, authoritative, concise. Do not copy a specific copyrighted character's voice.
- STT security requirements are in Section 11.

## 2.8 Current state

ASHWIN does not yet exist as a finished application. Do not tell the user to "install ASHWIN" until an actual APK has been built. The AI-assisted development environment (Antigravity) builds ASHWIN and is not part of ASHWIN's runtime.

---

# 3. CORE INVARIANT

## 3.1 Final invariant

> No context item reaches any AI model until current-request identity, authorization, scope, content-type, scanning, classification, and routing checks have passed.

This applies to everything that enters model context: laptop, Moto, Gmail, Calendar, GitHub, web, typed input, voice/STT output, metadata, tool results, and memory recall.

## 3.2 Highly protected data

**[RULE-03]** HIGHLY PROTECTED data never enters any AI model context, local or cloud.

Detection limits for natural-language input are stated in RULE-10. They do not weaken this rule for file, Moto, and connector data.

---

# 4. DATA CLASSIFICATION AND ROUTING

## 4.1 Classes

| Class | Meaning | Examples |
|---|---|---|
| PUBLIC | Intentionally public | public portfolio, public website, public GitHub repositories |
| PERSONAL | User information that is not PROTECTED or HIGHLY PROTECTED | non-sensitive preferences, ordinary personal notes, non-sensitive memory, non-sensitive planning information |
| PROTECTED | Information from private sources | Moto data, private laptop data, private Gmail, private Calendar, private GitHub, private documents, private filenames and metadata, private system/process/device information |
| HIGHLY PROTECTED | Credentials and secrets | passwords, API keys, private keys, OAuth tokens, refresh tokens, session cookies, recovery codes, authentication secrets |

HIGHLY PROTECTED material must also never appear in normal memory, prompts, conversation history, audit logs, debug logs, or source code.

## 4.2 Typed input and STT output

**[RULE-01]** All typed input and STT output → LOCAL AI by default. Cloud processing requires the consent policy in Section 4.5.

Typed input and STT output are classified PROTECTED by default.

## 4.3 Laptop and Moto output

- Every output from the private laptop connector is PROTECTED. This includes results of `find_file`, `find_folder`, `list_folder`, `open_folder`, `view_document`, `read_document_text`, `get_open_apps`, `get_processes`, and `get_connected_devices`. It covers filenames, folder names, directory structures, file metadata, application and process names and metadata, connected-device information, document contents, search results, and errors containing private system information.
- Everything retrieved from Moto storage is PROTECTED.
- Private Gmail, Calendar, and GitHub content is PROTECTED.
- The classification travels with the data through the whole pipeline, even when the output appears harmless.

## 4.4 Default routing

| Class | Route |
|---|---|
| PUBLIC | Cloud AI permitted per provider policy |
| PERSONAL | Local AI preferred; cloud only per the user's configured policy; no assumption of unrestricted cloud transmission |
| PROTECTED | Local AI; cloud requires explicit consent for the request unless the user deliberately configured a broader policy |
| HIGHLY PROTECTED | Never enters model context (RULE-03) |

The Router must not silently downgrade a classification and must not choose the strongest available model when doing so would expose protected information.

## 4.5 Access permission versus egress consent

Access permission and egress consent are separate decisions:

1. May ASHWIN retrieve this data?
2. May this data leave the device and be sent to a cloud AI provider?

Rules:

- Approval to access a source never authorizes cloud transmission.
- If local AI is unavailable and no consent exists, ASHWIN does not send protected data to cloud AI. It asks, for example: "The local AI is unavailable. Processing this private document with cloud AI would send its contents outside your devices. Allow this for this request?"
- Consent is per request by default (Allow once / Deny). It applies only to the described operation and is never silently broadened.
- A persistent "allow cloud by default for protected data" policy may exist in settings. Its default is OFF. HIGHLY PROTECTED data is excluded from any such policy.

## 4.6 Classification survives derivation

A summary or transformation of protected data remains PROTECTED, unless an explicit, justified reclassification mechanism exists. Extracted metadata remains PROTECTED when it reveals private information.

## 4.7 Origin tracking and minimization

- Context items carry their source, classification, cloud-processing approval state, and scan state.
- When AI processing is permitted, send only the minimum data required (only the necessary document or content, never the whole storage).

---

# 5. ROUTER-INGRESS GATE

**[RULE-04]** The AI Router accepts only a typed `ScannedClassifiedContext` object. Any context object lacking a valid scanned-and-classified state is rejected.

**[RULE-05]** Every source of model context passes through this gate: laptop, Moto, Gmail, Calendar, GitHub, web, typed input, STT output, metadata, and tool results. Memory writes and memory recall pass through the same gate.

Connector-side scanning remains as defense in depth. It does not replace the gate.

---

# 6. SOURCES, PERMISSIONS, AND UNTRUSTED CONTENT

## 6.1 Source domains

```text
PHONE  MOTO_STORAGE  LAPTOP  GMAIL  CALENDAR  GITHUB  LINKEDIN  WEB
```

Every request involving external data names a source. There is no implicit source selection, and sources are never silently combined.

## 6.2 Source selection

For requests that could refer to several sources (resumes, documents, projects, photos, reports, other files):

1. Use the user's configured preferred source, if one exists.
2. Otherwise ask, e.g. "Which should I search: your private Moto storage or your authorized laptop storage?"
3. If the user says "both" or "all", query each authorized source independently, each subject to its own permission rules, and return results separated by source.

If multiple matches exist, ask which one. Never choose silently.

## 6.3 Moto access permission

- Before access is granted, ASHWIN retrieves no private Moto contents or filenames. It may know only connection state: CONNECTED, OFFLINE, or UNPAIRED.
- When access is needed, ASHWIN asks: "Your private Moto storage requires permission. May I access it?" Only after approval does the connector query contents.
- V1 does not pre-index Moto contents. A future metadata index would be encrypted, protected by the same permission system, and must not reveal filenames before authorization.

## 6.4 Authorization pipeline

Data flow for private-source operations:

```text
USER INTENT → SOURCE SELECTION → AUTHENTICATION → ACCESS PERMISSION
→ TARGET VALIDATION → DATA CLASSIFICATION → AI ROUTING POLICY
→ LOCAL AI or CLOUD AI → CLOUD CONSENT CHECK WHEN REQUIRED
→ AI TOOL PROPOSAL → PERMISSION / CONFIRMATION
→ RESTRICTED CONNECTOR → RESULT VALIDATION → AUDIT
```

Every tool proposal, wherever it originated, must pass:

```text
Tool exists? → Source authorized? → Capability authorized?
→ Target valid? → Data policy satisfied? → Confirmation required?
→ User confirmation (if required) → Execute → Verify result → Audit
```

Not every step needs an interactive prompt, but every applicable gate is evaluated. No stage is skipped because the AI believes a request is harmless.

## 6.5 Laptop permission classes

| Class | Tools | Default |
|---|---|---|
| A — system information | `get_open_apps`, `get_processes`, `get_connected_devices` | Allowed after the laptop is paired and enabled; user can disable |
| B — scoped discovery | `find_file`, `find_folder`, `list_folder` | Allowed inside user-approved scopes; each scope is explicitly approved at setup |
| C — open / view | `open_folder`, `view_document`, `read_document_text` | Allowed inside authorized scopes; user can set "ask every time" |
| D — application launch | `open_allowed_app` | Confirmation required for each launch |

`read_document_text` is Class C. It requires the same authorized laptop scope and execution-time validation as `view_document`, and it returns content only through the Router gate (RULE-04, RULE-05).

No tool may exceed its class. `view_document` and `read_document_text` cannot modify, execute, delete, or upload a file or launch programs. `open_folder` cannot modify, execute, or delete. `get_processes` cannot terminate or start processes. A file operation never grants broader filesystem access.

## 6.6 Sensitive actions

These always require explicit confirmation: send email, modify GitHub (push, change code, delete), publish LinkedIn content, modify the public website, delete data, upload private data, and cloud processing of protected data. Reading untrusted content never counts as confirmation.

## 6.7 Untrusted content

Data can inform ASHWIN, but data cannot authorize ASHWIN.

Everything retrieved from external sources (documents, PDFs, emails, webpages, GitHub files, Moto files, laptop files) is untrusted data. It cannot grant or revoke permissions, authorize tools, change security policy, create tools, approve cloud transfer, or authorize email sending, GitHub changes, or laptop actions. Only the user, ASHWIN's hard-coded policy layer, and explicit confirmation can authorize actions.

Permission to read private data is not permission to upload it.

---

# 7. AUTHENTICATION, PAIRING, AND TRANSPORT

## 7.1 Common rules

- Use mature, well-reviewed protocols and libraries. No custom cryptography.
- There is no plaintext fallback on any ASHWIN channel. If authenticated encrypted communication cannot be established, the connection fails closed and no credentials, tokens, or private data are sent.
- Authorization never rests on IP address, MAC address, Wi-Fi or LAN membership, hostname, obscurity, or a secret URL.
- Identities are mutual, specific, and revocable.
- Prefer local/private-network access. No public Internet exposure unless absolutely necessary; remote access would be a separate security design.

## 7.2 Laptop pairing and revocation

```text
Install laptop agent → agent creates device identity → phone: "Pair Laptop"
→ matching code / QR shown on both → user confirms both
→ authenticated encrypted channel
```

- A random device on the same network cannot pair automatically.
- The user can revoke the pairing from ASHWIN, and the laptop agent can revoke its trust. After revocation, old credentials and keys are rejected, and a new pairing is required.
- All phone ↔ laptop traffic (filenames, directory metadata, document data, process and device information, tool requests and results, authentication material) uses the authenticated encrypted channel.

## 7.3 Moto pairing and revocation

- The Moto requires an explicit pairing process with a user-confirmed pairing identity or code. The resulting identity is stored securely.
- The user can revoke the Moto pairing. A revoked identity is rejected even if the Moto stays on the network. Re-pairing requires a new authenticated pairing.
- Moto failure message: "I can't establish a secure connection to your private storage."

## 7.4 Moto feasibility gate

No Moto connector implementation begins until the Moto G3 is technically verified for: Android version, available storage, RAM, network behavior, TLS capabilities, supported cryptographic libraries, background-service limits, charging and thermal behavior, ability to establish authenticated encrypted transport, and a maintained implementation path for the protocol.

The Moto is expected to be limited to Android 6.0. If authenticated encrypted transport cannot be implemented reliably, **do not build the Moto connector**. The security requirement is not weakened to suit the old phone. Security must not depend on the Moto's OS version: use strong authentication, scoped access, minimal exposed endpoints, request validation, and rate limiting where practical.

---

# 8. WINDOWS LAPTOP ENDPOINT

## 8.1 Purpose

The laptop agent is a restricted bridge, not a remote shell. The chain is: AI → approved tool → validation → restricted laptop agent → specific operation.

## 8.2 Tool list

The laptop agent exposes exactly ten tools:

| Tool | Input | Contract |
|---|---|---|
| `find_file` | query | Searches approved scopes only; returns file objects with agent-generated `file_id` |
| `find_folder` | query | Searches approved scopes only; returns `folder_id` |
| `list_folder` | `folder_id` | Lists a validated folder |
| `open_folder` | `folder_id` | Displays a validated folder in Explorer |
| `view_document` | `file_id` | Viewer only. Opens a hardened viewer on a temp copy. Returns no content to ASHWIN |
| `read_document_text` | `file_id` | Class C. Returns scanned document text through the Router gate only |
| `open_allowed_app` | `app_id` | Launches an allowlisted application with no arguments |
| `get_open_apps` | none | Read-only |
| `get_processes` | none | Read-only |
| `get_connected_devices` | none | Read-only |

**[RULE-06]** `read_document_text(file_id)` is the only V1 laptop path that returns file content to ASHWIN.

There is no generic `execute`, `shell`, `command`, `run`, `launch`, or `open_path` tool, and no hidden fallback that executes anything when a tool is missing or fails.

## 8.3 Forbidden capabilities

The agent never exposes: shell, CMD, PowerShell, arbitrary command, script, executable or process launching, project/test/build execution, software install or uninstall, file modification or deletion, shutdown/restart/sleep/hibernate, system setting changes, arbitrary application automation, unrestricted remote desktop, arbitrary URL launching, arbitrary file-association launching, arbitrary filesystem access. The restriction lives in the agent itself, never only in an AI prompt.

## 8.4 Directory scope

- The user approves directories during pairing (for example Documents, Downloads, Projects). Default: no directories approved.
- The agent never gains access to `C:\`, `C:\Windows`, `C:\Program Files`, `C:\ProgramData`, other users' directories, or network shares.
- `find_*` and `list_folder` operate only inside approved scopes.
- Downloads may hold untrusted files. Two independent checks are always required: directory authorization and file-type/viewer authorization.

## 8.5 Identifiers

**[RULE-08]** All IDs (`file_id`, `folder_id`, and any other agent-issued ID) are generated only by the laptop agent from a cryptographically secure RNG with at least 128 bits, unguessable (no counters, sequences, or embedded paths), held in memory only and never on disk, bound to one authenticated channel and the paired device identity, with a TTL of at most 5 minutes (absolute, not extended by use). Reconnection creates new IDs and invalidates all old ones.

Additional invalidation triggers: session end, revocation, scope change, agent restart.

- The AI cannot construct, modify, or extend an ID. The agent owns the ID-to-object mapping.
- The AI supplies IDs, never raw Windows paths, to any tool. `app_id` values come only from the agent's allowlist.
- Every `file_id` is bound at `find_file`, and every `folder_id` at `find_folder`, to three values: volume serial number, filesystem file ID, and canonical path. These values are verified at execution (RULE-07).
- A validated file object records: `file_id`, display name, approved scope, extension, detected content type, validation status. These values are informational only and are never trusted at execution time.

## 8.6 Single-handle validation and execution-time validation

**[RULE-07]** Both parts are mandatory.

**Part A — single-handle file processing.** The agent processes a source file through exactly one open handle:

1. Resolve `file_id` to its registered object (after Part B checks).
2. Open the source once: read-only, share mode denying write and delete, reparse points not followed (open the link itself, then reject it).
3. From that handle, verify: the handle's volume serial, file ID, and canonical path match all three bound values; the final path derived from the handle is inside an approved scope; it is a regular file (not a directory, device, pipe, or reparse point); it is not an alternate data stream; it is not on a UNC or network volume. Reject any mismatch, including parent-directory junction or reparse substitution.
4. Read the header from the same handle and check magic bytes.
5. Compare the detected type to the extension and the allowlist. Reject mismatches and unknown types.
6. Stream-copy from the same handle into an agent-owned temp file. Enforce the maximum size. The AI cannot choose the destination.
7. Close the source handle.
8. Re-verify signature and format sanity on the completed temp copy.
9. Only then continue: `view_document` opens the hardened viewer on the temp copy; `read_document_text` continues to Section 8.10.

The agent never reopens the original path after step 2. Failure to hold a single handle → REJECT. The agent holds a read-only, deny-write/delete handle on the verified temp copy until the viewer has loaded it. The viewer never receives the original path.

**Part B — execution-time validation.** Every tool that accepts any ID (`list_folder`, `open_folder`, `view_document`, `read_document_text`, and any future ID-accepting tool) re-validates at execution:

- the ID exists and is unexpired;
- it belongs to this session and paired device;
- pairing has not been revoked;
- the object still exists and is the expected type;
- the object's identity is unchanged: for both `file_id` and `folder_id`, the bound volume serial number, filesystem file ID, and canonical path match the object actually opened (folders are verified from an opened directory object, with reparse points not followed);
- the object is still inside an authorized scope, and that scope authorization is current;
- for files, the content type is re-detected (never read from cache);
- current-request permission requirements are satisfied.

Expired, revoked, stale, mismatched, or unknown IDs → REJECT. Scope change, reparse substitution, or a changed object type → REJECT.

## 8.7 Temp copy

The temp copy lives in an agent-owned private directory: ACL-restricted to the agent's user, created with exclusive access, not in Downloads or any user scope, not on network storage or a UNC path, not in an executable search location. It is deleted after use, and stale copies are purged on agent start.

## 8.8 Path security

The agent rejects or safely handles `..` traversal, absolute paths outside approved scopes, UNC paths and network shares, symbolic links, junctions, mount points, unauthorized reparse points, NTFS alternate data streams, and malformed Windows paths. String comparison alone is never sufficient; validation uses handle/object identity. In V1, reparse points are not followed.

## 8.9 `open_folder`

- Accepts only a previously validated `folder_id`, never a raw path.
- Before opening, verifies the target exists, is a directory, is inside an approved scope, is not UNC/network, does not cross an unauthorized reparse point, and passes Part B validation, including a match against the `folder_id`'s bound volume serial number, filesystem file ID, and canonical path. It revalidates immediately before use.
- Explorer never receives an arbitrary AI-controlled path or command-line arguments. `explorer.exe <arbitrary path>` is not a supported mechanism. Folder opening is never used to launch files.
- `open_folder` is the only way Explorer is started.
- Explorer resolves the path independently, so a residual TOCTOU race remains. It is documented (Section 17) and never described as atomic or race-free.

## 8.10 File viewing and reading

`view_document` never uses `ShellExecute(path)` or Windows default file associations. It selects an explicit hardened viewer for the temp copy and returns no file content to ASHWIN.

Laptop file content pipeline for AI use (`read_document_text`):

```text
identity → authorization → scope → single-handle / object identity validation
→ content type → temp copy → temp-copy verification → text extraction
→ complete secret scan → PROTECTED classification → Router gate
→ cloud-consent check → model
```

## 8.11 Document policy

- **Viewable formats (after validation):** TXT, PNG, JPG/JPEG, GIF, BMP, and PDF through the controlled viewer.
- **AI-readable formats (V1):** see Section 9.1.
- **Denied by default (until a dedicated safe-viewing design exists):** DOC, DOCX, XLS, XLSX, PPT, PPTX, SVG, HTML, HTM, XML. Legacy macro-capable formats (DOC, XLS, PPT) stay denied unless a hardened viewer exists. Any future Office support requires macros, DDE, and automatic execution disabled, external links controlled, and embedded active content disabled. Any future SVG support requires sanitizing or rasterizing so scripts cannot run.
- **Never opened or executed:** `.exe .com .bat .cmd .ps1 .psm1 .vbs .vbe .js .jse .wsf .wsh .msc .msi .msp .scr .cpl .lnk .url .dll`, and any other executable, script, or launcher format. Unknown types → DENY.
- **Content-type verification:** reliable signatures are checked for PNG, JPEG, GIF, PDF, and BMP. A mismatch between extension and content → REJECT. Plain text follows the TXT rule (Section 9.3). If content cannot be confidently classified → REJECT.
- Mark-of-the-Web is not a security boundary. Absence of MOTW does not mean trusted. File extensions and Windows file associations never decide what is safe.
- **Hardened PDF viewing:** the specific viewer component is named at implementation. JavaScript, launch actions, embedded executable or content launching, and automatic external application launching are disabled. External network and content access is restricted or disabled where practical. PDF is never treated as inherently passive.

## 8.12 Applications

- `open_allowed_app(app_id)` accepts only an application ID. It takes no executable path, no command-line arguments, and no workspace path. The agent maps ID → executable; the AI cannot create or modify mappings.
- Initial allowlist: `NOTEPAD`, `CALCULATOR`. Each addition needs individual security review.
- Excluded: `FILE_EXPLORER`, `VS_CODE`, `CMD`, `POWERSHELL`, `TERMINAL`.
- VS Code may be added later only after a separate design covers workspace restoration, extension behavior, workspace trust, task execution, launch configurations, and command-line arguments.
- Any future argument support requires an explicitly defined safe schema per argument.

## 8.13 System information tools

`get_open_apps`, `get_processes`, and `get_connected_devices` are read-only. `get_processes` cannot terminate, start, inject into, modify, suspend, or resume processes. `get_connected_devices` gives no control over devices. AI-visible metadata rules are in Section 9.7.

## 8.14 Privilege

The laptop agent runs as a normal user-level process with least privilege. It does not require administrator rights and does not run as SYSTEM.

---

# 9. CONTENT EXTRACTION AND SECRET SCANNING

## 9.1 AI-readable files (V1)

Only TXT and text-extractable PDF are AI-readable. Text is extracted first, then the extracted text and explicitly allowlisted metadata are scanned. Images, scanned PDFs, unsupported binaries, and unextractable content are withheld from AI (the user may still view them where validation allows).

## 9.2 Extractor isolation

**[RULE-12]** PDF and text extraction on untrusted input, wherever it runs (laptop agent or phone), runs in an isolated, low-privilege, network-disabled process under the limits in Section 15. Any crash, timeout, parser error, or resource exhaustion → the output is discarded and AI delivery is denied. The extractor returns text only, over a bounded channel, and nothing partial reaches the Router.

## 9.3 TXT validation

A file is accepted as TXT only if all of these hold:

- extension is `.txt`;
- encoding is strictly valid UTF-8 (with or without BOM) or UTF-16 with a BOM, decoded before scanning;
- size is within the TXT limit in Section 15.

Reject if any of these apply: any NUL byte in UTF-8 content; any invalid UTF-8 sequence; control characters above the limit in Section 15 (tab, LF, CR, and form feed excluded); an executable or archive signature at the start (MZ, ELF, PK, %PDF, and similar); a line longer than the limit in Section 15.

If the agent cannot confidently classify the file as text → deny AI access. (Under the existing rule that unclassifiable files are not opened, such a file is also not viewed.)

## 9.4 Scanner scope and placement

The scanner covers, before anything reaches the Router:

- laptop document text via `read_document_text`;
- Moto `read`, `download`, `search` results, filenames, metadata, and downloaded files;
- laptop filenames, folder names, window titles, device names, and error text;
- Gmail, Calendar, GitHub, web results, and other tool results;
- typed input and STT output.

Placement: laptop content is scanned in the laptop agent before it leaves the laptop. Moto content is scanned in ASHWIN Core on the phone on the decrypted content; the Moto stays a plain storage endpoint. The Router-ingress gate (RULE-04, RULE-05) is the universal check.

The scanner detects at least: API keys and access tokens (known provider formats and generic high-entropy strings), passwords and credential assignments, private keys (PEM/OpenSSH), OAuth/refresh/bearer tokens and JWTs, session cookies, recovery/backup codes, connection strings with embedded credentials, and similar credential material.

## 9.5 Redact-or-withhold and fail-closed handling

**[RULE-09]** For file, Moto, and connector data, secret handling is redact-or-withhold and fail-closed:

- Detected secrets are replaced with typed placeholders (e.g. `[REDACTED:API_KEY]`). Only redacted content may reach a model.
- Raw detected secrets never enter model context, prompts, conversation history, memory, audit logs, or debug logs. The audit log records only the file ID, scan result, and the count and types of redactions, never the secret or a surrounding excerpt.
- Content is fully buffered and completely scanned before any AI delivery. There is no partial forwarding.
- Scanner health is checked on every request. A missing, unloaded, stale, failed, timed-out, or oversized scan → DENY AI delivery.
- Content that cannot be scanned (images without a text pass, scanned PDFs, unsupported encodings) may be shown to the user but is not sent to any AI model in V1.
- A region that cannot be reliably redacted is withheld.

## 9.6 Natural-language limitation

**[RULE-10]** Natural-language secret detection is best-effort. Pattern-based scanning cannot guarantee detection of every secret, for example a password written in ordinary prose. Scanning reduces exposure; it does not replace the routing policy. Redacted content remains PROTECTED and follows the consent rules, and the user may configure stricter handling (for example local AI only) for specific folders.

For typed input and STT output: HIGHLY PROTECTED material must never intentionally be supplied to an AI model. A detected secret in typed or STT input is redacted and the user is warned. Accidental secrets that evade detection cannot be guaranteed to be caught. Documentation must state this limitation and must not describe scanning as a guarantee. This softening applies only to natural-language input; it does not soften RULE-09.

## 9.7 Metadata pipeline

**[RULE-14]** All laptop, Moto, and tool metadata passes through one mandatory pipeline. No metadata reaches the model outside it:

```text
source authentication → authorization → scope validation → explicit field allowlist
→ secret scan / redaction → classification → Router gate → routing / consent
```

- **Scope validation** means the approved directory scope (laptop), `ASHWIN_STORAGE` (Moto), or the authorized API scope (connector tools).
- **Explicit field allowlist:** only allowlisted fields survive, and all other fields are dropped before scanning. V1 laptop allowlist: name, size, date, and type. V1 Moto allowlist: the same four fields. Each connector's declared operation schema (Section 12) must list its allowlisted fields. A source or tool with no declared allowlist contributes no metadata to the model. Adding a field requires a new version of this specification.
- `get_processes` returns no command lines.
- Any window title, device name, or error text that reaches the model, whether as an allowlisted field or as a tool message, is scanned before Router ingress.
- Classification is PROTECTED (Section 4.3). Metadata never becomes less protected because it looks harmless.
- Scanner-health and fail-closed handling follow RULE-09, and consent follows Section 4.5.

## 9.8 File locations

**[RULE-15]** The model never receives unrestricted filesystem paths. ASHWIN Core retains the validated location associated with each object (`file_id`, `folder_id`) and presents a user-facing location separately when needed. The AI receives only the minimum safe location representation required for the conversation.

- V1 minimum safe location representation: the user-chosen approved-scope label (for example "Projects") for laptop objects, or the source label `MOTO_STORAGE` for Moto objects, together with the object's allowlisted name. Nothing more: no drive letters, user-profile directories, absolute or full relative paths, or system directories.
- The scope label passes through the metadata pipeline (RULE-14) like any other field.
- Core displays the full user-facing location itself (for example as a UI element), not through model-generated text. Core-rendered locations are not added to model context or to conversation history sent to the model.
- This does not relax RULE-08: the AI supplies IDs, never paths, to tools.

---

# 10. MOTO STORAGE ENDPOINT

- Exposes only the dedicated `ASHWIN_STORAGE` area. The internal folder structure (for example Documents, Resumes, Projects, Photos, Reports, Other) is decided at implementation. ASHWIN has no access to unrelated Moto data.
- Capabilities: `list`, `search`, `read`, `download`. Future `upload` and `delete` need their own explicit authorization and confirmation.
- No `shell`, `execute`, `command`, `process`, or device-control capability exists.
- Requests require authenticated encrypted transport (Section 7) and prior access permission (Section 6.3).

Moto content pipeline for AI use:

```text
authentication → access permission → decrypt → bounded complete buffering
→ content-type verification → text extraction → secret scan
→ PROTECTED classification → Router gate → cloud-consent check → model
```

The entire file is buffered within the size limits in Section 15 before any processing. No bytes are forwarded to the AI before buffering, extraction, and scanning are complete. Moto search results, filenames, metadata (RULE-14), and downloaded files are covered. Any later AI read of a downloaded file passes through the Router gate again.

---

# 11. VOICE AND SPEECH-TO-TEXT

**[RULE-11]** V1 STT must be verifiably on-device. The generic Android `SpeechRecognizer` and any "offline" or "prefer offline" flag are not accepted as proof of offline execution. If offline execution cannot be verified, voice input is unavailable and typed input is offered instead.

Verification criterion (adopted V1 default): the STT component runs with network access blocked (a separate process or module with no network permission, or a test with the network disabled) and still transcribes.

**[RULE-02]** Cloud STT requires separate explicit consent. It is disabled by default. Raw microphone audio is never sent to cloud STT automatically. If cloud STT is ever enabled, each request needs its own explicit per-request consent before audio leaves the device, separate from cloud-AI consent for text.

STT output is subject to RULE-01 and Section 9.6.

---

# 12. ONLINE CONNECTORS

- Each connector declares: identity/authentication method, supported operations, operation schemas, data classes, permission requirements, confirmation requirements, supported API capabilities, and audit requirements. ASHWIN calls only declared operations, and the AI cannot invent a capability.
- Use official APIs. Do not scrape or reverse-engineer private interfaces unless a separately reviewed and explicitly approved architecture exists. Do not assume an API supports read, write, publish, message, search, or delete because the website does. If an API lacks a capability, ASHWIN says it is unavailable. This is especially important for LinkedIn.
- The connector, not the AI, owns credentials, access tokens, refresh tokens, authentication state, request signing, secure transport, and provider-specific validation. The AI receives only the minimum information needed. The user enters credentials themselves through proper authentication flows. Credentials never go into source code, GitHub, normal memory, or prompts, and are kept in secure token storage.
- Examples: Gmail: `read_email`, `search_email`, `send_email` (confirmation required). GitHub: `read_repository`, `read_issues`, `modify_repository` (confirmation required). LinkedIn: whatever the currently authorized API supports.
- Private Gmail and private GitHub content is PROTECTED. Public data (for example the public portfolio) follows the PUBLIC route, and credentials are never included merely because public data was requested.
- Each service requires separate user authorization. ASHWIN has no automatic access to any of them.

---

# 13. AUDIT LOG

Record: pairing events, authentication results and failures, source selected, permission requests and decisions, data classification, cloud-egress decisions, AI provider selected and provider failures, tool requests, object resolution and validation results, confirmations, and execution, rejection, and failure results including connector failures.

Never log passwords, tokens, private keys, or raw protected file contents. Scan-result logging follows RULE-09.

---

# 14. FAIL-CLOSED PRINCIPLE

If ASHWIN cannot determine that an operation is authorized → do not execute. Each of these → DENY:

- authentication failure (do not connect);
- encryption unavailable (do not transmit);
- invalid target;
- target outside authorized scope;
- unknown or unclassifiable file type or unsafe content (do not open);
- revoked pairing;
- missing cloud consent (do not send);
- unsupported connector capability.

No security boundary is weakened to complete a user request, and no configuration may weaken these behaviors.

---

# 15. LIMITS (V1 ADOPTED DEFAULTS)

Configurable downward only, never upward.

| Item | Limit |
|---|---|
| Source file size | 5 MB |
| Extracted text size | 1 MB |
| PDF pages | 50 |
| TXT file size | 1 MB |
| TXT control characters | more than 1% of characters → reject |
| TXT single line length | 64 KB |
| Extraction timeout | 10 s |
| Scan timeout | 5 s per item |
| Total AI-delivery time per request | 15 s |
| AI-visible metadata field length | 256 characters |
| ID TTL | 5 minutes, absolute |

---

# 16. MANDATORY SECURITY TESTS

**[RULE-13]** All tests below are mandatory and must pass before ASHWIN is considered security-complete. No existing test may be removed or weakened. Unless stated otherwise, the expected result is REJECT / DENY.

## A. Paths and filesystem
- **T-01** Path traversal: `..`, `..\..\secret`, `../secret`, `C:\unauthorized`, `C:\Users\...\unauthorized`.
- **T-02** Absolute path outside scope; raw path used to bypass `file_id` / `folder_id`.
- **T-03** UNC and network paths: `\\server\share`, `\\127.0.0.1\share`, `\\localhost\share`.
- **T-04** Reparse points: symlinks, junctions, mount points, unauthorized reparse points (not followed).
- **T-05** NTFS alternate data streams (`file.txt:stream`).
- **T-06** Malformed Windows paths.
- **T-07** Directory outside the approved laptop scope.
- **T-08** Parent-directory junction swap.

## B. File type and content
- **T-09** Executable disguised as a safe file (`malware.png`, `document.pdf`, `image.txt`).
- **T-10** Magic-byte / content mismatch (exe renamed `.png` or `.txt`, non-PDF as `.pdf`, non-JPEG as `.jpg`); rejected before the temp copy is created.
- **T-11** Unknown or ambiguous file type.
- **T-12** Denied executable/script types (EXE, BAT, CMD, PS1, VBS, JS, MSI, LNK, URL).
- **T-13** Macro-capable Office documents and active SVG.
- **T-14** PDF active content (JavaScript, launch actions, embedded executable content, automatic external application launches, unnecessary network access). Expected: safe controlled viewing or REJECT. Never opened through the Windows file association.
- **T-15** TXT edge cases: NUL bytes, invalid UTF-8, control-heavy content, executable renamed `.txt`, UTF-16 without BOM, oversize file → AI access denied.

## C. Races and identity
- **T-16** TOCTOU: replace a validated file between validation and open/read, and between validation and temp copy. Expected: the swap is blocked or the operation fails, and the viewer never receives unvalidated bytes.
- **T-17** Single-handle race: swap the source (rename, replace, junction substitution) between validation and copy and between header read and copy. Expected: blocked or fails, and instrumentation confirms no second open of the original path.
- **T-18** Temp-copy verification: alter the temp copy after copying → post-copy check fails, viewer not launched.
- **T-19** Handle-identity mismatch (volume serial, file ID, or canonical path differs from the bound values).
- **T-20** Execution-time re-validation: change type, move out of scope, or revoke authorization after `find_file` but before `view_document` or `read_document_text`.
- **T-21** Forged, guessed, or edited `file_id` / `folder_id`; IDs from another session; session-mismatched IDs; expired IDs.
- **T-22** Stale or replayed IDs after revocation, scope removal, agent restart, TTL expiry, or reconnect.

## D. Authentication and transport
- **T-23** Unauthorized LAN connection (no valid identity, completed pairing, authenticated session, or encrypted transport).
- **T-24** Failed authentication → no tool execution, no data access, no fallback connection.
- **T-25** Encryption unavailable → fail closed, never downgrade to plaintext.
- **T-26** Invalid or revoked device (laptop and Moto).
- **T-27** Unknown device, incorrect pairing credentials, replayed authentication material.

## E. Capabilities and injection
- **T-28** Arbitrary application launch (executable-path injection into `open_allowed_app`).
- **T-29** Application abuse: arbitrary command-line arguments, arbitrary path argument to Explorer, workspace restoration, extension/task execution.
- **T-30** Arbitrary command execution (`cmd`, `powershell`, `shell`, `terminal`, `execute`, `run_command`). Expected: capability does not exist.
- **T-31** Prompt injection: untrusted content tells ASHWIN to ignore the security policy or send a file. Expected: treated as data, no permission change, no tool authorization, no cloud-egress authorization.

## F. Routing and consent
- **T-32** PROTECTED laptop metadata (filenames, process list, app list, connected devices) routed to cloud AI without explicit consent while local AI is unavailable. Expected: rejected, nothing transmitted, user asked.
- **T-33** Moto filenames, metadata, and search results routed to cloud without consent.
- **T-34** Typed input and STT output routed to cloud without consent.
- **T-35** Cloud STT without per-request consent → no audio leaves the device.
- **T-36** Forged Moto reference.
- **T-37** Structural Router test: any context object without a valid scanned-and-classified state is rejected.

## G. Secrets, scanning, and extraction
- **T-38** Planted secrets (API key, password, private key block, session cookie) inside an otherwise valid `.txt` and `.pdf` in an authorized laptop scope and inside a Moto document. Expected: raw secrets absent from model context, prompts, history, memory, and logs; placeholders present.
- **T-39** Secret in a filename or metadata → redacted before the Router.
- **T-40** Secret in a process command line, window title, or error text.
- **T-41** Secret split across a chunk boundary.
- **T-42** Secret inside a compressed PDF stream or annotation.
- **T-43** Secret in UTF-16 or base64 form.
- **T-44** Prose password: remains PROTECTED and is blocked from cloud without consent.
- **T-45** HIGHLY PROTECTED typed input (a known-format key is redacted and the user warned; a prose password stays PROTECTED).
- **T-46** Gmail recovery code never reaches model context.
- **T-47** HIGHLY PROTECTED memory recall never reaches a model.
- **T-48** Scanner failure: error, timeout, oversized input → content withheld.
- **T-49** Scanner unavailable (missing, unloaded, stale) → AI delivery denied.
- **T-50** Partial-forward prevention: nothing is delivered before the scan completes, and a failure after processing starts delivers no earlier portion.
- **T-51** Unscannable content (image, scanned PDF): viewable by the user, not sent to any AI model.
- **T-52** Extractor crash, timeout, memory exhaustion, or malformed PDF → no content reaches the Router and output is discarded.

## H. Tests added in v1.0.1
- **T-53** `folder_id` identity: mismatch of bound volume serial number, filesystem file ID, or canonical path; folder replaced by a file (changed object type); scope change; reparse substitution; stale or expired ID.
- **T-54** `read_document_text` (Class C): rejected outside an authorized scope or after failed execution-time validation; content reaches a model only through the Router gate.
- **T-55** Metadata pipeline: metadata that skips any stage (allowlist, scan/redaction, classification, Router gate) is rejected; non-allowlisted fields (for example process command lines) are dropped; a source with no declared allowlist contributes no metadata.
- **T-56** Path exposure: no absolute or full path appears in model context, prompts, or history sent to the model; Core-rendered user-facing locations are absent from model history.
- **T-57** Moto ordering: access permission is checked before any read; no bytes reach the AI before buffering, extraction, and scanning complete; an over-limit Moto file is denied.

---

# 17. RESIDUAL RISKS AND SECURITY CLAIM

## 17.1 Documented residual risks

- Explorer resolves folder paths independently, so a residual TOCTOU race remains for `open_folder`.
- Another process running as the same Windows user can touch the temp copy. ACLs reduce this but do not eliminate it.
- Pattern-based scanning is best-effort (RULE-10).
- The Moto's old Android version constrains what transport security is achievable (Section 7.4).

## 17.2 Security language

Do not claim ASHWIN makes compromise impossible or arbitrary execution "architecturally impossible". The accurate statement is:

> ASHWIN's initial endpoints do not expose a general-purpose command execution interface. They use authenticated encrypted communication, explicit source selection, scoped permissions, least privilege, target validation, controlled viewing, application allowlists, data-sensitivity policies, and separate cloud-egress consent to reduce the authority and attack surface of the system.

---

# 18. DEVELOPMENT ORDER

1. **ASHWIN V0.1:** Android app, conversation interface, voice architecture, AI Router, model abstraction, memory, permissions, tool manager, security layer, audit logging, settings.
2. Moto connector (only after the feasibility gate in Section 7.4 passes).
3. Restricted laptop connector.
4. Online connectors, one at a time: Gmail, Calendar, GitHub, LinkedIn, portfolio, internet search, job search, then others.

Each integration is independently permissioned and testable, and each connector passes security testing independently. The user's role: prepare devices, install generated software, authorize services, grant permissions, make security decisions, test the system, and enter credentials only through secure authentication screens.

---

# 19. OPEN ITEMS

No open items remain in v1.0.1. Items O-1 to O-4 from v1.0.0 are resolved:

| Item | Status | Resolution |
|---|---|---|
| O-1 `read_document_text` permission class | RESOLVED (v1.0.1) | Class C, with the same scope and execution-time validation as `view_document`; content only through the Router gate (Section 6.5) |
| O-2 `folder_id` identity binding | RESOLVED (v1.0.1) | Bound to volume serial number, filesystem file ID, and canonical path; verified at execution (Sections 8.5, 8.6, 8.9) |
| O-3 metadata pipeline | RESOLVED (v1.0.1) | RULE-14 (Section 9.7) |
| O-4 file locations shown to the user | RESOLVED (v1.0.1) | RULE-15 (Section 9.8) |

The v1.0.0 Moto pipeline ordering contradiction is also resolved (Section 10).

---

*End of ASHWIN-SPEC v1.0.1 (2026-09-30).*
