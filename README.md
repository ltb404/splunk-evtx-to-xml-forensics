# Convert-EvtxToXml

A PowerShell script that converts Windows Event Log (`.evtx`) files to XML **at scale**, across many hosts, with a SHA1 hash report for every file and a resilient multi-tier fallback that keeps going when individual files or logs hit `wevtutil`'s various failure modes.

Built for offline/forensic-style workflows: a folder full of `.evtx` files copied off many machines, needing to become clean, well-formed, parseable XML — reliably, unattended, with an audit trail.

## Why not just run `wevtutil` directly?

You can, for one file. This script exists because at scale you'll hit several real problems `wevtutil` doesn't handle gracefully on its own:

- Some logs have accompanying metadata for full message rendering, some don't — even on the same host.
- Certain event/message combinations crash rendering entirely on some Windows versions.
- Some specific files fail to open at all, for reasons unrelated to file corruption.
- Piping `wevtutil`'s Unicode output through PowerShell's normal pipeline silently corrupts non-ASCII text.
- Huge files (multi-GB Security logs) give zero progress feedback and can look "stuck" for hours when they're actually fine.
- Nothing tracks integrity (hashes) across a large batch by default.

This script handles all of that so you don't have to rediscover it the hard way.

## Requirements

- Windows (uses `wevtutil.exe`, built in).
- PowerShell 5.1+ or PowerShell 7+.
- Run elevated if you need to read ACL-restricted logs (e.g. `Security.evtx`).

## Expected folder layout

```
SourceRoot\
    HOST01\
        Security.evtx
        System.evtx
        Application.evtx
        LocaleMetaData\        <- optional, per-file, enables full message rendering
    HOST02\
        Security.evtx
        ...
    ...
```

One subfolder per host. A `LocaleMetaData` folder (sometimes seen spelled `LocalMetaData`) next to a specific `.evtx` — not the whole host folder — was produced by `wevtutil archive-log` on the source machine and lets that specific log be fully rendered offline. It's completely normal for only some logs on a host to have this (commonly just Security/System/Application) while others (Applications and Services logs, etc.) are plain copied files. The script checks per-file, not per-host, so this mixed situation is handled automatically.

## Usage

```powershell
.\Convert-EvtxToXml.ps1 -SourceRoot D:\Collections -OutputRoot D:\Collections_XML
```

This walks every host subfolder, converts every `.evtx` it finds, mirrors the folder structure under `-OutputRoot`, and writes a CSV hash report alongside it.

```powershell
# Re-run and overwrite existing output, with verbose logging
.\Convert-EvtxToXml.ps1 -SourceRoot D:\Collections -OutputRoot D:\Collections_XML `
    -CsvReportPath D:\Reports\hashes.csv -Overwrite -Verbose

# See exactly what would happen without converting anything
.\Convert-EvtxToXml.ps1 -SourceRoot D:\Collections -OutputRoot D:\Collections_XML -WhatIf
```

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-SourceRoot` | Yes | — | Root folder containing one subfolder per host. |
| `-OutputRoot` | Yes | — | Where converted `.xml` files are written (mirrors the source tree). |
| `-CsvReportPath` | No | `<OutputRoot>\EvtxConversion_HashReport.csv` | Path for the hash report. |
| `-MetaDataFolderNames` | No | `LocaleMetaData`, `LocalMetaData` | Folder name(s) checked next to each `.evtx`. |
| `-Overwrite` | No | off | Re-convert files whose output already exists (default: skip, but still hash + report them). |
| `-ProgressPollSeconds` | No | `5` | How often the progress bar refreshes while converting a large file. |

Standard `-WhatIf` / `-Verbose` support included.

## How conversion works: 4-tier fallback

Rather than failing a file outright on the first problem, the script tries progressively less-demanding options, in order, until one succeeds:

1. **`wevtutil qe "<file>" /lf:true /f:RenderedXml`** — full message rendering, only attempted if a metadata folder sits beside the file.
2. **`wevtutil qe "<file>" /lf:false /f:RenderedXml`** — rendering via whatever's registered locally.
3. **`wevtutil qe "<file>" /lf:false /f:Xml`** — raw structured XML, no message rendering. Still contains every `<Data Name='...'>value</Data>` field — you only lose the pre-rendered "friendly" message sentence, not the actual data.
4. **.NET `EventLogReader` fallback** — used only if every `wevtutil` attempt fails identically, including a plain header read, with errors like `The specified channel path is invalid` / `Failed to open event query`. This is a `wevtutil`-specific limitation around internal channel-path resolution that can trip even on a perfectly intact file; `Get-WinEvent` (and the .NET API behind it) doesn't share the limitation, so tier 4 uses that directly as a last resort.

Every file's outcome is recorded in the CSV's `RenderLevel` column, so you can see at a glance which tier a given file needed.

### A note on `/e:<root>` and Error 87

You might expect the script to use `wevtutil`'s own `/e:<root>` flag to make its output a single well-formed XML document. It deliberately doesn't: combining `/e` with `/f:RenderedXml` is a known trigger for **`Failed to render events. Error=87`** (`ERROR_INVALID_PARAMETER`) on certain events — data-dependent, so it fails intermittently rather than consistently, which makes it a nasty silent-data-loss trap at scale. Instead, `wevtutil` writes raw, unwrapped `<Event>...</Event>` output, and the script wraps that into a valid `<Events>...</Events>` document itself afterward via a fast streaming byte copy — no meaningful overhead even on multi-GB files, and the bug never gets a chance to trigger.

## Progress reporting

`wevtutil` gives no native progress feedback, so the script builds its own:

1. Before converting, it reads the `.evtx` header (`wevtutil gli`) to get the total record count — fast, since it doesn't require rendering.
2. While conversion runs, it polls the growing output file every few seconds, counts completed `<Event>` elements, and shows a live `Write-Progress` bar with an estimated percentage, event count, MB written, and elapsed time.
3. If the header can't be read (e.g. a dirty log), it falls back to showing raw counts and elapsed time without a percentage — so you can still tell it's alive rather than hung.

A multi-GB `Security.evtx` with `/f:RenderedXml` can genuinely take a long time — often 50–300 events/second is normal, since every event requires a message-template lookup. That's not a hang; the progress bar is there specifically so you can tell the difference.

## Output encoding

Files are written as **UTF-8 without a BOM**, matching what `wevtutil` actually produces when its output is redirected (confirmed by inspecting raw bytes — it starts with `<` directly, not a UTF-16 BOM, despite console output sometimes suggesting otherwise). Output is captured via `Start-Process -RedirectStandardOutput` rather than PowerShell's `>` operator specifically to avoid a known issue where piping `wevtutil`'s output through the normal PowerShell pipeline corrupts non-ASCII characters in rendered messages.

## CSV report columns

| Column | Description |
|---|---|
| `Hostname` | Derived from the host subfolder name. |
| `SourceFile` / `SourceSHA1` / `SourceSizeBytes` | Source `.evtx` details. |
| `OutputFile` / `OutputSHA1` / `OutputSizeBytes` | Converted `.xml` details. |
| `LocalMetaDataUsed` | Whether a metadata folder was found next to this specific file. |
| `RenderLevel` | Which of the 4 tiers actually succeeded (or `PreExisting/Unknown` if the file was skipped because output already existed). |
| `Status` | `Success`, `EmptyOutput`, or `Failed`. |
| `ConversionUtcTime` | Timestamp of the conversion attempt. |

## Resuming an interrupted or partial run

Existing output files are skipped by default (not re-converted), so if a batch run gets interrupted or you're iterating on fixes, just re-run the same command — it will only touch files that don't already have output, or that previously failed (0-byte/missing output isn't treated as "already exists"). Use `-Overwrite` to force a full re-conversion of everything instead.

## Troubleshooting

| Symptom | Cause | What the script already does |
|---|---|---|
| Conversion looks stuck on a huge file | `/f:RenderedXml` renders every event individually — genuinely slow, not hung | Live progress bar shows events/MB/elapsed so you can confirm it's still moving. |
| `The specified channel path is invalid` / `Failed to open event query` | `wevtutil`'s internal channel-path resolution can fail even on an intact file | Falls through the 4-tier chain automatically; tier 4 (.NET) bypasses `wevtutil` entirely. |
| `Failed to render events. Error=87` | Known bug combining `/e:<root>` with `/f:RenderedXml`, data-dependent | Script never uses `/e`; wraps output itself afterward instead. |
| Only some logs on a host have full rendering | Metadata (`LocaleMetaData`) was only archived for some logs, not others | Detected per-file automatically; falls back to lower tiers for logs without it. |
| Output looks garbled / wrong encoding downstream | Consumer assumes UTF-16 when files are actually UTF-8, no BOM | Check the consumer's charset setting rather than the script — verify actual bytes with a hex dump if unsure. |

# Index-XmlToSplunk

Scripts and Splunk configuration to bulk-index `wevtutil`-converted Windows Event Log XML files into Splunk via `splunk add oneshot`, with correct per-event parsing, hostnames, and field extraction — not one giant blob per file.

Pairs with `Convert-EvtxToXml.ps1` (the EVTX → XML converter) — this repo picks up where that one leaves off.

## Contents

| File | Purpose |
|---|---|
| [`Index-XmlToSplunk.ps1`](./Index-XmlToSplunk.ps1) | Bulk indexer for **Windows** Splunk hosts (PowerShell). |
| [`index-xml-to-splunk.sh`](./index-xml-to-splunk.sh) | Bulk indexer for **Linux** Splunk hosts (bash), same behavior. |
| [`props.conf`](./props.conf) | Custom sourcetype so Splunk breaks events correctly and extracts standard fields. |
| [`transforms.conf`](./transforms.conf) | Extracts individual `Data` fields (`LogonType`, `LogonGuid`, `TargetUserName`, etc.) from Windows event payloads. |

## Why a custom sourcetype at all?

Splunk's built-in `XmlWinEventLog` sourcetype is built for **live** forwarder-style collection, not a single file containing potentially hundreds of thousands of `<Event>` records wrapped in one `<Events>` root. Point it at a converted file and you'll typically get a handful of Splunk events per file (often just one), each one a huge multi-event blob — not what you want. Splunk's auto-detected `xml-2` sourcetype has the same fundamental problem: no event-boundary logic for this shape. The `props.conf`/`transforms.conf` here fix that.

---

## 1. Deploy the Splunk configuration

### Self-managed Splunk

Copy both files into an app directory, e.g.:

```
$SPLUNK_HOME/etc/apps/search/local/props.conf
$SPLUNK_HOME/etc/apps/search/local/transforms.conf
```

Then restart Splunk, or reload without a restart:

```
| extract reload=t
```

(or Settings → Source Types in Splunk Web, which triggers a reload)

### Splunk Cloud / no filesystem access

Recreate both stanzas via Splunk Web:

- **Settings → Source Types → New Source Type** — name it `wevtutil_rendered_xml`, set category to `Structured`, and enter the settings from [`props.conf`](./props.conf) in the advanced fields (`LINE_BREAKER`, `TIME_PREFIX`, `MAX_TIMESTAMP_LOOKAHEAD`, `TIME_FORMAT`, `KV_MODE`, `CHARSET`, `SHOULD_LINEMERGE`).
- **Settings → Fields → Field Transforms → New** — name it `wevtutil_eventdata_kv`, paste in the regex and format from [`transforms.conf`](./transforms.conf).
- Then attach the transform to the sourcetype: Settings → Source Types → `wevtutil_rendered_xml` → Advanced → add a Field Extraction (Report) pointing at `wevtutil_eventdata_kv`.

### Validate before a full index run

The inline sourcetype preview panel was removed in newer Splunk versions. Instead:

- **Web UI**: Settings → Add Data → Upload → pick a small sample file → the preview screen shows event breaking and `_time` before you commit to indexing.
- **CLI** (faster to iterate): `splunk add oneshot sample.xml -sourcetype wevtutil_rendered_xml -index test`

Build a tiny sample file first — 2–3 `<Event>` blocks copied out of a real converted file, wrapped in `<Events>...</Events>` — so each iteration is fast rather than testing against a multi-GB file.

---

## 2. Index the XML files

Both scripts do the same thing: recursively find `.xml` files, derive the hostname from a specific segment of each file's path, and run `splunk add oneshot` per file with a local checkpoint so re-runs don't double-index anything.

### ⚠️ `oneshot` does not de-duplicate

Unlike a `monitor` input, `splunk add oneshot` has no fishbucket tracking — run it twice on the same file and it gets indexed twice. Both scripts maintain their own checkpoint file, updated after every file, so interrupting and re-running picks up where it left off instead of double-indexing everything already done.

### Windows

```powershell
splunk login    # cache a CLI session so credentials never appear on the command line

.\Index-XmlToSplunk.ps1 -SourceRoot D:\Collections_XML -Index winlogs `
    -SourceType wevtutil_rendered_xml -HostSegmentIndex 5
```

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-SourceRoot` | Yes | — | Root folder to search recursively. |
| `-Index` | Yes | — | Target Splunk index. |
| `-SourceType` | Yes | — | Sourcetype to assign (`wevtutil_rendered_xml` if using the config above). |
| `-HostSegmentIndex` | No | `5` | 1-based segment of the full absolute path, split on `\`, that contains the hostname. |
| `-FileFilter` | No | `*.xml` | File filter. |
| `-SplunkBin` | No | `C:\Program Files\Splunk\bin\splunk.exe` | Path to `splunk.exe`. |
| `-Username` / `-Password` | No | — | CLI auth. Omit both and run `splunk login` first instead. |
| `-StateFilePath` | No | `<SourceRoot>\_splunk_oneshot_state.csv` | Checkpoint file. |
| `-CsvReportPath` | No | `<SourceRoot>\SplunkOneshot_Report_<timestamp>.csv` | Per-run result report. |
| `-Limit` | No | — | Only process the first N files — for validation runs. |
| `-Force` | No | off | Re-index files even if the checkpoint says they succeeded before. |

Supports `-WhatIf` / `-Verbose`.

### Linux

```bash
chmod +x index-xml-to-splunk.sh
/opt/splunk/bin/splunk login

./index-xml-to-splunk.sh --source-root /home/you/xmldata --index winlogs \
    --sourcetype wevtutil_rendered_xml --host-segment 5
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--source-root` | Yes | — | Root folder to search recursively. |
| `--index` | Yes | — | Target Splunk index. |
| `--sourcetype` | Yes | — | Sourcetype to assign. |
| `--host-segment` | No | `5` | 1-based segment of the full path (leading `/` stripped, split on `/`) that contains the hostname. |
| `--file-filter` | No | `*.xml` | File filter (glob). |
| `--splunk-bin` | No | `/opt/splunk/bin/splunk` | Path to the `splunk` binary. |
| `--username` / `--password` | No | — | CLI auth. Omit both and run `splunk login` first instead. |
| `--state-file` | No | `<source-root>/_splunk_oneshot_state.tsv` | Checkpoint file (tab-separated). |
| `--report-file` | No | `<source-root>/splunk_oneshot_report_<timestamp>.tsv` | Per-run result report. |
| `--limit N` | No | — | Only process the first N files. |
| `--force` | No | off | Re-index files even if already checkpointed. |
| `--dry-run` | No | off | Print what would happen without indexing anything. |

Requires bash 4.4+ (any current Linux distro). Reports/checkpoints are tab-separated rather than CSV specifically to avoid quoting issues with file paths — opens fine in Excel/LibreOffice/Sheets as a tab-delimited import.

### Recommended workflow (either platform)

```
1. Dry run / -WhatIf   -> confirm the derived hostnames are actually correct
2. -Limit 2             -> validate end-to-end against a couple of real files
3. Full run              -> index everything
```

Segment counting is the most common thing to get wrong on the first try — for a Windows path `C:\WORK\MW_Converted\HOST01\Security.xml`, `C:` is segment 1; for a Linux path `/home/you/xmldata/HOST01/Security.xml`, `home` is segment 1 (leading `/` is stripped before counting). Always confirm with a dry run before a real batch.

---

## Splunk configuration reference

### `props.conf`

```ini
[wevtutil_rendered_xml]
NO_BINARY_CHECK = true
SHOULD_LINEMERGE = false
CHARSET = UTF-8
LINE_BREAKER = ()(?=<Event xmlns=)
TIME_PREFIX = <TimeCreated SystemTime='
MAX_TIMESTAMP_LOOKAHEAD = 500
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
KV_MODE = xml
REPORT-eventdata = wevtutil_eventdata_kv
FIELDALIAS-eventid  = Event.System.EventID AS EventID Event.System.EventID AS EventCode
FIELDALIAS-computer = Event.System.Computer AS Computer Event.System.Computer AS host_computer
FIELDALIAS-provider = Event.System.Provider.Name AS SourceName Event.System.Provider.Name AS Provider
FIELDALIAS-channel  = Event.System.Channel AS Channel Event.System.Channel AS LogName
category = Structured
pulldown_type = true
disabled = false
```

What each non-obvious setting does:

- **`LINE_BREAKER = ()(?=<Event xmlns=)`** — a zero-width lookahead that splits the file right before every `<Event xmlns=...>`, without consuming any text, so each Splunk event contains exactly one Windows event.
- **`SHOULD_LINEMERGE = false`** — critical; otherwise Splunk tries to re-merge the pretty-printed multi-line XML using its own line-based heuristics, fighting `LINE_BREAKER`.
- **`CHARSET = UTF-8`** — `wevtutil`'s redirected output (as produced by the converter script) is plain UTF-8 with no BOM, not UTF-16 — mismatching this is what causes fields to render as garbled/CJK-looking characters.
- **`TIME_PREFIX = <TimeCreated SystemTime='`** — note the **single quotes**; `wevtutil` writes XML attributes with `'`, not `"`. Getting this wrong causes Splunk to fall back to scanning the raw event for any date-looking string, which can land on a completely unrelated value inside the event data.
- **`MAX_TIMESTAMP_LOOKAHEAD = 500`** — the `TimeCreated` element can sit 300–400+ characters into an event, well past Splunk's low default lookahead; too small a value causes the same "wrong timestamp" symptom as above.
- **`KV_MODE = xml`** — required for any field auto-extraction at all (`category = Structured` alone does *not* auto-extract fields, despite being easy to assume it does).
- **`FIELDALIAS-*`** — map the dotted `Event.System.*` paths XML extraction produces into the plain field names (`EventID`, `Computer`, etc.) people actually search on.

### `transforms.conf`

```ini
[wevtutil_eventdata_kv]
REGEX = <Data Name='([^']*)'>([^<]*)</Data>
FORMAT = $1::$2
REPEAT_MATCH = true
```

Windows events store their real payload as repeated same-named sibling elements (`<Data Name='LogonType'>5</Data>`, `<Data Name='LogonGuid'>...</Data>`, etc.). Generic XML/`spath`-style extraction can't split those into individual fields on its own — it just gives you one multivalue field with no names attached. `REPEAT_MATCH = true` walks every `Data` element in the event, and `FORMAT = $1::$2` turns the `Name` attribute into the field name and the element text into its value — giving you real, individually-searchable fields like `LogonType`, `LogonGuid`, `TargetUserName`, `WorkstationName`, etc.

This is search-time extraction, so it applies retroactively to already-indexed events too — no reindex needed if you add/fix it after the fact (unlike `LINE_BREAKER`/`TIME_PREFIX`, which are index-time and do require reindexing already-ingested data to take effect).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| One giant Splunk event per file / only a handful of events per host | Default sourcetype has no event-boundary logic for this file shape | Use the custom `LINE_BREAKER` sourcetype above; requires reindexing already-ingested bad data. |
| Fields look like Chinese/CJK characters | `CHARSET` mismatched to the file's real encoding | Verify actual file encoding (check the first bytes) and set `CHARSET` to match — expect UTF-8, no BOM. |
| Timestamps wildly wrong (e.g. far-future dates) | Wrong quote character in `TIME_PREFIX`, or `MAX_TIMESTAMP_LOOKAHEAD` too small | Use single quotes; set lookahead to 500+. |
| No `EventID`/`EventCode`/`Computer` fields | Missing `KV_MODE = xml` | Add it — `category = Structured` alone doesn't extract anything. |
| Missing fields like `LogonType`, `LogonGuid` | Generic XML extraction can't split repeated same-named `<Data Name='X'>` elements | Add the `transforms.conf` regex extraction. |
| Re-running the indexing script re-indexes everything | Ran with `--force`/`-Force`, or deleted the checkpoint file | Expected — that's what those do. Omit `-Force`/`--force` for normal resumable runs. |
| `splunk add oneshot` fails with a permission error | The account running `splunkd` doesn't have read access to the source folder | Check ownership/permissions on the folder holding the XML files, especially on Linux under another user's home directory. |

---

## License

MIT — use, modify, and redistribute freely. Contributions and PRs welcome.

## Disclaimer

Not affiliated with Splunk Inc. Tested against real-world multi-host XML collections, but your Splunk version, event volume, and custom fields may surface edge cases not covered here — please open an issue if you hit one.
Not affiliated with Microsoft. Tested against real-world multi-host `.evtx` collections, but very large environments, unusual providers, or heavily customized Windows builds may surface edge cases not covered here — please open an issue if you hit one.

