<#
.SYNOPSIS
    Converts Windows Event Log (.evtx) files to well-formed, fully-rendered XML using
    wevtutil, and records the SHA1 hash of every source .evtx and converted .xml file
    in a CSV report.

.DESCRIPTION
    Expects a source root folder laid out one subfolder per host, e.g.:

        SourceRoot\
            HOST01\
                Security.evtx
                System.evtx
                LocalMetaData\        <- (or LocaleMetaData) used for full message rendering
            HOST02\
                Security.evtx
                LocalMetaData\
            ...

    For every .evtx file found, the script tries, in order, until one succeeds:

        1) wevtutil qe "<file>" /lf:true  /f:RenderedXml   (only if a
           LocalMetaData/LocaleMetaData folder sits next to the file)
        2) wevtutil qe "<file>" /lf:false /f:RenderedXml
        3) wevtutil qe "<file>" /lf:false /f:Xml
        4) .NET EventLogReader (same API Get-WinEvent uses) - only reached if all
           wevtutil attempts fail identically, including plain 'gli', with errors
           like "The specified channel path is invalid" / "Failed to open event
           query". This happens when wevtutil's own channel-path resolution fails
           even though the file is perfectly readable (confirmed by Get-WinEvent
           succeeding on the same file when wevtutil cannot). Tier 4 bypasses
           wevtutil entirely and streams each record's raw XML directly via .NET,
           producing the same <Event xmlns=...> structure inside an <Events> root,
           so downstream parsing doesn't need to differ based on which tier a file
           went through. Like tier 3, it has no message rendering.

    Note the wevtutil tiers deliberately do NOT use /e:<root> (wevtutil's own
    "wrap output in a root element" flag). Combining /e with /f:RenderedXml is a
    known trigger for "Failed to render events. Error=87" on certain events -
    data-dependent, so it fails intermittently rather than consistently. Instead,
    wevtutil writes raw, unwrapped <Event>...</Event> output to a temp file, and
    the script wraps that into a valid <Events>...</Events> document itself
    afterward via a streaming byte copy (Wrap-RawEventXml) - cheap even on
    multi-GB files, and avoids the bug entirely.

    Some channels fail outright under /lf:true with errors like "The specified
    channel path is invalid" or "Failed to open event query" - this happens when
    the LocalMetaData folder doesn't have complete metadata for that particular
    channel (common for less-common "Applications and Services" logs), not because
    the .evtx itself is unreadable. Rather than hard-failing that file, the script
    falls back to plain rendering and, if that also fails, to raw (unrendered) XML,
    and finally to the .NET fallback if even that fails.
    Raw Xml still contains every <Data Name='...'>value</Data> field - you only
    lose the pre-rendered "friendly" message sentence, not the structured data - so
    downstream parsing (e.g. into Splunk via KV_MODE=xml or a Data-element regex)
    is unaffected by which tier a given file ended up using. The CSV report's
    RenderLevel column records which tier succeeded for each file, so you can spot
    which files only got raw XML and, if you care about the rendered message text
    for those specific ones, address their LocalMetaData separately.

    /lf:true tells wevtutil to use the LocalMetaData/LocaleMetaData folder sitting next
    to the .evtx file to fully render event messages (needed when analyzing logs away
    from the machine they came from).

    Output is captured via Start-Process -RedirectStandardOutput rather than PowerShell's
    '>' operator, because wevtutil emits UTF-16 and piping it through the normal
    PowerShell pipeline/console encoding is a known way to corrupt non-ASCII characters
    in rendered event messages. Start-Process redirection writes the child process's
    raw bytes straight to disk. The final <Events> root wrapping is then added by the
    script itself (see the /e:<root> note above) rather than by wevtutil.

    The resulting XML tree mirrors the source tree under -OutputRoot, and a single CSV
    report is produced with the SHA1 hash (and size) of every source/converted pair.

    PROGRESS: before converting each file, the script reads the evtx header
    (via 'wevtutil gli', a fast operation that doesn't require rendering) to get the
    total event/record count. While wevtutil is running, the script polls the growing
    output file every few seconds, counts how many <Event > elements have been written
    so far, and shows a live Write-Progress bar with an estimated percentage, event
    count, MB written, and elapsed time. If the record count can't be determined (e.g.
    a dirty/corrupt log), it falls back to showing raw counts/size without a percentage.

.PARAMETER SourceRoot
    Root folder containing one subfolder per host (each holding .evtx files and,
    optionally, a LocalMetaData/LocaleMetaData folder).

.PARAMETER OutputRoot
    Root folder where converted .xml files will be written. Folder structure under
    each host is mirrored from the source.

.PARAMETER CsvReportPath
    Path to the CSV hash report to create. Defaults to
    "<OutputRoot>\EvtxConversion_HashReport.csv".

.PARAMETER MetaDataFolderNames
    Folder name(s) to look for beside each .evtx to decide whether /lf:true can be
    used. Defaults to 'LocalMetaData' and 'LocaleMetaData' (both spellings show up
    in the wild depending on tool/OS version).

.PARAMETER Overwrite
    If specified, re-converts and overwrites .xml files that already exist in
    OutputRoot. Without this switch, existing output files are skipped (but are
    still hashed and included in the CSV).

.PARAMETER ProgressPollSeconds
    How often (in seconds) to poll the growing output file and refresh the
    progress bar while a conversion is running. Defaults to 5. Lower it for more
    frequent updates on very large files, raise it to reduce overhead.

.EXAMPLE
    .\Convert-EvtxToXml.ps1 -SourceRoot D:\Collections -OutputRoot D:\Collections_XML

.EXAMPLE
    .\Convert-EvtxToXml.ps1 -SourceRoot D:\Collections -OutputRoot D:\Collections_XML `
        -CsvReportPath D:\Reports\hashes.csv -Overwrite -Verbose

.NOTES
    - Run this on a Windows machine (wevtutil.exe is required).
    - Run elevated if you need to read logs such as Security.evtx, depending on ACLs.
    - Conversion "success" here means wevtutil exited 0 and produced a non-empty file;
      it does not guarantee every message string rendered (that depends on the
      LocalMetaData/provider data actually being complete for that log).
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$SourceRoot,

    [Parameter(Mandatory)]
    [string]$OutputRoot,

    [Parameter()]
    [string]$CsvReportPath,

    [Parameter()]
    [string[]]$MetaDataFolderNames = @('LocaleMetaData', 'LocalMetaData'),

    [Parameter()]
    [switch]$Overwrite,

    [Parameter()]
    [int]$ProgressPollSeconds = 5
)

$ErrorActionPreference = 'Stop'

# ---- Resolve dependencies / defaults -----------------------------------------------

$wevtutilCmd = Get-Command wevtutil.exe -ErrorAction SilentlyContinue
if (-not $wevtutilCmd) {
    throw "wevtutil.exe was not found on PATH. This script must run on Windows with the Event Log tools available."
}

if (-not (Test-Path -LiteralPath $OutputRoot)) {
    New-Item -Path $OutputRoot -ItemType Directory -Force | Out-Null
}

if (-not $CsvReportPath) {
    $CsvReportPath = Join-Path $OutputRoot 'EvtxConversion_HashReport.csv'
}
$csvDir = Split-Path -Parent $CsvReportPath
if ($csvDir -and -not (Test-Path -LiteralPath $csvDir)) {
    New-Item -Path $csvDir -ItemType Directory -Force | Out-Null
}

$results = [System.Collections.Generic.List[object]]::new()

# ---- Helpers ------------------------------------------------------------------------

function Get-Sha1Hash {
    param([Parameter(Mandatory)][string]$Path)
    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA1 -ErrorAction Stop).Hash
    }
    catch {
        Write-Warning "    Could not hash '$Path': $($_.Exception.Message)"
        return $null
    }
}

function Test-LocalMetaDataPresent {
    param([Parameter(Mandatory)][string]$FolderPath)
    foreach ($name in $MetaDataFolderNames) {
        $candidate = Join-Path $FolderPath $name
        if (Test-Path -LiteralPath $candidate -PathType Container) {
            return $true
        }
    }
    return $false
}

function Test-InsideMetaDataFolder {
    param([Parameter(Mandatory)][string]$DirectoryPath)
    $segments = $DirectoryPath -split '\\'
    foreach ($name in $MetaDataFolderNames) {
        if ($segments -contains $name) { return $true }
    }
    return $false
}

function Get-EvtxRecordCount {
    # Reads the evtx header via 'wevtutil gli' to get the total event count.
    # This is a fast header read (no message rendering), so it works even on
    # very large files. Returns $null if it can't be determined (e.g. dirty log).
    param([Parameter(Mandatory)][string]$Path)
    try {
        $gliOutput = & $wevtutilCmd.Source gli "$Path" 2>&1
        $line = $gliOutput | Where-Object { $_ -match 'numberOfLogRecords\s*:\s*(\d+)' } | Select-Object -First 1
        if ($line -and $line -match 'numberOfLogRecords\s*:\s*(\d+)') {
            return [int64]$Matches[1]
        }
    }
    catch { }
    return $null
}

function Invoke-WevtutilWithProgress {
    # Starts wevtutil asynchronously and polls the growing output file to estimate
    # progress, based on how many <Event ...> elements have been written so far
    # versus the total record count reported by the evtx header.
    param(
        [Parameter(Mandatory)][string]$WevtutilPath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$ErrorPath,
        [Parameter()][int64]$TotalRecords,
        [Parameter()][string]$ActivityLabel = 'Converting',
        [Parameter()][int]$ProgressId = 1,
        [Parameter()][int]$PollSeconds = 5
    )

    $proc = Start-Process -FilePath $WevtutilPath `
        -ArgumentList $ArgumentList `
        -NoNewWindow -PassThru `
        -RedirectStandardOutput $OutputPath `
        -RedirectStandardError $ErrorPath

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $lastReadPosition = 0L
    $eventsSoFar = 0L
    $leftoverText = ''

    while (-not $proc.HasExited) {
        Start-Sleep -Seconds $PollSeconds

        # Tail-read only the bytes appended since the last poll, so we don't
        # re-scan the whole (potentially multi-GB) file every cycle.
        try {
            if (Test-Path -LiteralPath $OutputPath) {
                $fs = [System.IO.File]::Open($OutputPath, 'Open', 'Read', 'ReadWrite')
                try {
                    $fs.Seek($lastReadPosition, 'Begin') | Out-Null
                    $len = $fs.Length - $lastReadPosition
                    if ($len -gt 0) {
                        $buffer = New-Object byte[] $len
                        [void]$fs.Read($buffer, 0, $len)
                        $lastReadPosition = $fs.Length
                        # wevtutil writes UTF-16LE
                        $chunkText = $leftoverText + [System.Text.Encoding]::Unicode.GetString($buffer)
                        $matches = [regex]::Matches($chunkText, '<Event ')
                        $eventsSoFar += $matches.Count
                        # Keep a small tail in case a tag got split across the chunk boundary
                        $leftoverText = if ($chunkText.Length -gt 32) { $chunkText.Substring($chunkText.Length - 32) } else { $chunkText }
                    }
                }
                finally {
                    $fs.Dispose()
                }
            }
        }
        catch {
            # File may be momentarily locked/inaccessible for reading - just skip this poll
        }

        $elapsed = $sw.Elapsed.ToString('hh\:mm\:ss')
        $outSizeMB = if (Test-Path -LiteralPath $OutputPath) { [math]::Round((Get-Item -LiteralPath $OutputPath).Length / 1MB, 1) } else { 0 }

        if ($TotalRecords -and $TotalRecords -gt 0) {
            $pct = [math]::Min(99, [math]::Round(($eventsSoFar / $TotalRecords) * 100, 1))
            Write-Progress -Id $ProgressId -Activity $ActivityLabel `
                -Status "$eventsSoFar / $TotalRecords events  |  $outSizeMB MB written  |  elapsed $elapsed" `
                -PercentComplete $pct
        }
        else {
            # No total record count available - show an indeterminate/size-based status instead
            Write-Progress -Id $ProgressId -Activity $ActivityLabel `
                -Status "$eventsSoFar events written  |  $outSizeMB MB written  |  elapsed $elapsed (total unknown)" `
                -PercentComplete -1
        }
    }

    Write-Progress -Id $ProgressId -Activity $ActivityLabel -Completed
    $sw.Stop()

    return $proc
}

function Convert-EvtxViaDotNet {
    # Last-resort fallback for files where wevtutil fails at EVERY tier (including plain
    # 'gli') with errors like "The specified channel path is invalid" / "Failed to open
    # event query" - even though the file itself is intact. This happens because
    # wevtutil performs its own channel-path resolution before reading, and that
    # resolution can fail for reasons unrelated to the file's actual readability.
    # Get-WinEvent / the underlying .NET EventLogReader class goes through the same
    # Windows Event Log API but does not hit this specific failure mode, so this
    # function uses it directly as a bypass. Output shape matches wevtutil's
    # (one <Event xmlns=...>...</Event> per record inside an <Events> root), so
    # downstream parsing (Splunk LINE_BREAKER etc.) does not need to differ per tier.
    # Rendering is not available here either way (same limitation as /f:Xml) - this
    # produces raw structured XML only.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter()][string]$ActivityLabel = 'Converting (.NET fallback)',
        [Parameter()][int]$ProgressId = 1,
        [Parameter()][int]$ReportEveryN = 2000
    )

    Add-Type -AssemblyName System.Core -ErrorAction SilentlyContinue

    $totalRecords = $null
    try {
        $session = New-Object System.Diagnostics.Eventing.Reader.EventLogSession
        $logInfo = $session.GetLogInformation($Path, [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
        if ($logInfo.RecordCount) { $totalRecords = $logInfo.RecordCount }
    }
    catch { }

    $count = 0L
    $consecutiveErrors = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $writer = $null
    $reader = $null

    try {
        # UTF-8 without BOM, matching what wevtutil's redirected output actually produces
        # (confirmed earlier: files start with 0x3C, no BOM) - keeps CHARSET = UTF-8 in
        # Splunk consistent regardless of which tier produced a given file.
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $writer = New-Object System.IO.StreamWriter($OutputPath, $false, $utf8NoBom)
        $writer.WriteLine('<Events>')

        $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Path, [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
        $query.TolerateQueryErrors = $true
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

        while ($true) {
            $evt = $null
            try {
                $evt = $reader.ReadEvent()
                $consecutiveErrors = 0
            }
            catch {
                $consecutiveErrors++
                if ($consecutiveErrors -ge 5) {
                    Write-Warning "    .NET fallback: 5 consecutive unreadable records, stopping early at $count events."
                    break
                }
                continue
            }
            if ($null -eq $evt) { break }

            try {
                $writer.WriteLine($evt.ToXml())
                $count++
                if (($count % $ReportEveryN) -eq 0) {
                    $elapsed = $sw.Elapsed.ToString('hh\:mm\:ss')
                    if ($totalRecords -and $totalRecords -gt 0) {
                        $pct = [math]::Min(99, [math]::Round(($count / $totalRecords) * 100, 1))
                        Write-Progress -Id $ProgressId -Activity $ActivityLabel `
                            -Status "$count / $totalRecords events  |  elapsed $elapsed" -PercentComplete $pct
                    }
                    else {
                        Write-Progress -Id $ProgressId -Activity $ActivityLabel `
                            -Status "$count events written  |  elapsed $elapsed (total unknown)" -PercentComplete -1
                    }
                }
            }
            finally {
                $evt.Dispose()
            }
        }

        $writer.WriteLine('</Events>')
        Write-Progress -Id $ProgressId -Activity $ActivityLabel -Completed
        return [PSCustomObject]@{ Success = ($count -gt 0); EventCount = $count; Error = $null }
    }
    catch {
        Write-Progress -Id $ProgressId -Activity $ActivityLabel -Completed
        return [PSCustomObject]@{ Success = $false; EventCount = $count; Error = $_.Exception.Message }
    }
    finally {
        if ($writer) { $writer.Dispose() }
        if ($reader) { $reader.Dispose() }
    }
}

function Wrap-RawEventXml {
    # wevtutil's /e:<root> flag (used to make its output a single well-formed XML
    # document) has a known bad interaction with /f:RenderedXml: certain events fail
    # to render with "Failed to render events. Error=87" (ERROR_INVALID_PARAMETER)
    # when /e is present, even though the same events render fine without it. To
    # avoid this entirely, wevtutil is now run WITHOUT /e, producing raw concatenated
    # <Event>...</Event> elements with no wrapping root - and this function wraps
    # that raw output into a valid <Events>...</Events> document itself, via a
    # streaming byte copy so multi-GB files don't need to be loaded into memory.
    param(
        [Parameter(Mandatory)][string]$RawPath,
        [Parameter(Mandatory)][string]$FinalPath
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $out = [System.IO.File]::Open($FinalPath, 'Create', 'Write', 'None')
    try {
        $header = $utf8NoBom.GetBytes("<Events>`n")
        $out.Write($header, 0, $header.Length)

        $inStream = [System.IO.File]::Open($RawPath, 'Open', 'Read', 'Read')
        try {
            $inStream.CopyTo($out)
        }
        finally {
            $inStream.Dispose()
        }

        $footer = $utf8NoBom.GetBytes("`n</Events>`n")
        $out.Write($footer, 0, $footer.Length)
    }
    finally {
        $out.Dispose()
    }
}

# ---- Main -----------------------------------------------------------------------------

$hostFolders = Get-ChildItem -LiteralPath $SourceRoot -Directory

if (-not $hostFolders) {
    Write-Warning "No host subfolders found directly under '$SourceRoot'."
}

foreach ($hostFolder in $hostFolders) {

    $hostName = $hostFolder.Name
    Write-Host "==== Host: $hostName ====" -ForegroundColor Cyan

    $evtxFiles = Get-ChildItem -LiteralPath $hostFolder.FullName -Filter '*.evtx' -File -Recurse |
        Where-Object { -not (Test-InsideMetaDataFolder -DirectoryPath $_.DirectoryName) }

    if (-not $evtxFiles) {
        Write-Warning "  No .evtx files found for host '$hostName'."
        continue
    }

    $hostOutputRoot = Join-Path $OutputRoot $hostName
    if (-not (Test-Path -LiteralPath $hostOutputRoot)) {
        New-Item -Path $hostOutputRoot -ItemType Directory -Force | Out-Null
    }

    foreach ($evtx in $evtxFiles) {

        # Mirror any subfolder structure under the host folder (usually none, but safe if present)
        $relativeDir = $evtx.DirectoryName.Substring($hostFolder.FullName.Length).TrimStart('\')
        $destDir = if ($relativeDir) { Join-Path $hostOutputRoot $relativeDir } else { $hostOutputRoot }
        if (-not (Test-Path -LiteralPath $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }

        $destXmlPath = Join-Path $destDir ($evtx.BaseName + '.xml')
        $errLogPath  = Join-Path $destDir ($evtx.BaseName + '.wevtutil.err.log')

        $useLocalMetaData = Test-LocalMetaDataPresent -FolderPath $evtx.DirectoryName

        $alreadyExists = (Test-Path -LiteralPath $destXmlPath) -and -not $Overwrite
        $renderLevel = $null

        if ($alreadyExists) {
            Write-Host "  Skipping (exists): $($evtx.Name)" -ForegroundColor DarkYellow
            $renderLevel = 'PreExisting/Unknown'
        }
        else {
            $sizeMB = [math]::Round($evtx.Length / 1MB, 1)
            Write-Host "  Converting: $($evtx.Name)  ($sizeMB MB)  [LocalMetaData: $useLocalMetaData]"

            # Get total record count up front (fast header read) so we can show a real percentage.
            $totalRecords = Get-EvtxRecordCount -Path $evtx.FullName
            if ($totalRecords) {
                Write-Host "    Total records: $totalRecords"
            }
            else {
                Write-Host "    Total records: unknown (could not read header - progress will show counts only)"
            }

            # Try progressively less-demanding options if the query itself fails to open
            # (e.g. "The specified channel path is invalid" / "Failed to open event query"),
            # which happens when LocalMetaData is missing/incomplete for a particular
            # channel rather than being a problem with the .evtx file itself.
            $attempts = [System.Collections.Generic.List[object]]::new()
            if ($useLocalMetaData) {
                $attempts.Add([PSCustomObject]@{ Lf = '/lf:true';  Format = '/f:RenderedXml'; Label = 'lf:true + RenderedXml (full render)' })
            }
            $attempts.Add([PSCustomObject]@{ Lf = '/lf:false'; Format = '/f:RenderedXml'; Label = 'lf:false + RenderedXml (local providers only)' })
            $attempts.Add([PSCustomObject]@{ Lf = '/lf:false'; Format = '/f:Xml';         Label = 'lf:false + raw Xml (no message rendering)' })

            $succeeded = $false
            $renderLevel = $null
            $lastErrText = $null

            foreach ($attempt in $attempts) {

                if ($succeeded) { break }

                Write-Host "    Attempt: $($attempt.Label)"

                $argList = @(
                    'qe'
                    ('"{0}"' -f $evtx.FullName)
                    $attempt.Lf
                    $attempt.Format
                    # Deliberately no /e:<root> here - combining it with /f:RenderedXml is a
                    # known trigger for "Failed to render events. Error=87" on certain events.
                    # wevtutil instead writes raw, unwrapped <Event>...</Event> output to a
                    # temp file, which is wrapped into a valid <Events>...</Events> document
                    # afterward via Wrap-RawEventXml (streaming, so this is cheap even on
                    # multi-GB files).
                )

                $rawTempPath = "$destXmlPath.rawtmp"

                if ($PSCmdlet.ShouldProcess($evtx.FullName, "Convert to '$destXmlPath' ($($attempt.Label))")) {
                    try {
                        $proc = Invoke-WevtutilWithProgress -WevtutilPath $wevtutilCmd.Source `
                            -ArgumentList $argList `
                            -OutputPath $rawTempPath `
                            -ErrorPath $errLogPath `
                            -TotalRecords $totalRecords `
                            -ActivityLabel "Converting $hostName\$($evtx.Name) [$($attempt.Label)]" `
                            -ProgressId 1 `
                            -PollSeconds $ProgressPollSeconds

                        $rawSize = if (Test-Path -LiteralPath $rawTempPath) { (Get-Item -LiteralPath $rawTempPath).Length } else { 0 }

                        if ($proc.ExitCode -eq 0 -and $rawSize -gt 0) {
                            Wrap-RawEventXml -RawPath $rawTempPath -FinalPath $destXmlPath
                            Remove-Item -LiteralPath $rawTempPath -Force -ErrorAction SilentlyContinue

                            $outSize = if (Test-Path -LiteralPath $destXmlPath) { (Get-Item -LiteralPath $destXmlPath).Length } else { 0 }
                            if ($outSize -gt 0) {
                                Write-Host "    Done ($($attempt.Label))." -ForegroundColor Green
                                $succeeded = $true
                                $renderLevel = $attempt.Label
                            }
                            else {
                                $lastErrText = "Wrap step produced 0-byte output"
                                Write-Warning "    Failed ($($attempt.Label)): $lastErrText"
                            }
                        }
                        else {
                            $lastErrText = if (Test-Path -LiteralPath $errLogPath) { (Get-Content -LiteralPath $errLogPath -Raw) } else { "Exit code $($proc.ExitCode), 0-byte output" }
                            Write-Warning "    Failed ($($attempt.Label)): $lastErrText"
                            Remove-Item -LiteralPath $rawTempPath -Force -ErrorAction SilentlyContinue
                            Remove-Item -LiteralPath $destXmlPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        $lastErrText = $_.Exception.Message
                        Write-Warning "    Failed ($($attempt.Label)): $lastErrText"
                        Remove-Item -LiteralPath $rawTempPath -Force -ErrorAction SilentlyContinue
                        Remove-Item -LiteralPath $destXmlPath -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                    # -WhatIf: don't actually try further tiers, nothing was run
                    break
                }
            }

            if (-not $succeeded) {
                Write-Host "    Attempt: .NET EventLogReader fallback (bypasses wevtutil's channel-path check)"
                if ($PSCmdlet.ShouldProcess($evtx.FullName, "Convert to '$destXmlPath' (.NET EventLogReader fallback)")) {
                    try {
                        $dotNetResult = Convert-EvtxViaDotNet -Path $evtx.FullName -OutputPath $destXmlPath `
                            -ActivityLabel "Converting $hostName\$($evtx.Name) [.NET fallback]" -ProgressId 1

                        $outSize = if (Test-Path -LiteralPath $destXmlPath) { (Get-Item -LiteralPath $destXmlPath).Length } else { 0 }

                        if ($dotNetResult.Success -and $outSize -gt 0) {
                            Write-Host "    Done (.NET fallback, $($dotNetResult.EventCount) events)." -ForegroundColor Green
                            $succeeded = $true
                            $renderLevel = ".NET EventLogReader fallback (unrendered, $($dotNetResult.EventCount) events)"
                        }
                        else {
                            $lastErrText = if ($dotNetResult.Error) { $dotNetResult.Error } else { "0 events read" }
                            Write-Warning "    Failed (.NET fallback): $lastErrText"
                            Remove-Item -LiteralPath $destXmlPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        $lastErrText = $_.Exception.Message
                        Write-Warning "    Failed (.NET fallback): $lastErrText"
                        Remove-Item -LiteralPath $destXmlPath -Force -ErrorAction SilentlyContinue
                    }
                }
            }

            if (-not $succeeded) {
                Write-Warning "    All conversion attempts failed for '$($evtx.Name)'. Last error: $lastErrText"
            }

            if ((Test-Path -LiteralPath $errLogPath) -and (Get-Item -LiteralPath $errLogPath).Length -eq 0) {
                Remove-Item -LiteralPath $errLogPath -Force
            }
        }

        # ---- Hashing / report row ----
        $sourceHash = Get-Sha1Hash -Path $evtx.FullName
        $destExists = Test-Path -LiteralPath $destXmlPath
        $destHash   = if ($destExists) { Get-Sha1Hash -Path $destXmlPath } else { $null }
        $destSize   = if ($destExists) { (Get-Item -LiteralPath $destXmlPath).Length } else { 0 }

        $status = if ($destExists -and $destHash -and $destSize -gt 0) { 'Success' }
                  elseif ($destExists -and $destSize -eq 0) { 'EmptyOutput' }
                  else { 'Failed' }

        $results.Add([PSCustomObject]@{
            Hostname          = $hostName
            SourceFile        = $evtx.FullName
            SourceSHA1        = $sourceHash
            SourceSizeBytes   = $evtx.Length
            OutputFile        = $destXmlPath
            OutputSHA1        = $destHash
            OutputSizeBytes   = $destSize
            LocalMetaDataUsed = $useLocalMetaData
            RenderLevel       = $renderLevel
            Status            = $status
            ConversionUtcTime = (Get-Date).ToUniversalTime().ToString('o')
        })
    }
}

# ---- Write report ------------------------------------------------------------------

$results | Sort-Object Hostname, SourceFile | Export-Csv -Path $CsvReportPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Done. $($results.Count) file(s) processed." -ForegroundColor Green
Write-Host "CSV report: $CsvReportPath" -ForegroundColor Green

$failCount = ($results | Where-Object { $_.Status -ne 'Success' }).Count
if ($failCount -gt 0) {
    Write-Warning "$failCount file(s) did not convert cleanly. Check Status column and any *.wevtutil.err.log files in the output tree."
}
