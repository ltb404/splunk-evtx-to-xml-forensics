<#
.SYNOPSIS
    Recursively finds converted event-log XML files under a root folder and indexes
    each one into Splunk via 'splunk add oneshot', deriving the hostname from a
    specific segment of each file's full path.

.DESCRIPTION
    Expects a layout like:

        SourceRoot\
            HOST01\
                Security.xml
                Application.xml
            HOST02\
                Security.xml
            ...

    For a full path such as:
        D:\LOGS_TO_CHECK\FOLDER\HOST01\Security.xml

    splitting on '\' gives segments (1-based):
        1: D:
        2: LOGS_TO_CHECK
        3: FOLDER
        4: HOST01
        5: Security.xml

    -HostSegmentIndex tells the script which 1-based segment of the FULL absolute
    path is the hostname. Because this depends on how deep SourceRoot itself sits,
    it's a parameter rather than something inferred automatically - set it to match
    your actual paths (run once with -WhatIf and check the "host=" values printed
    before doing a real run).

    For every matching file, the script runs:

        splunk.exe add oneshot "<file>" -index <Index> -sourcetype <SourceType> -hostname <host> [-auth user:pass]

    via Start-Process (so exit code / stdout / stderr are captured cleanly), logs the
    result to a CSV report, and records successfully indexed files in a checkpoint
    file so re-running the script after an interruption does not re-index files
    ('oneshot' has no built-in de-duplication the way a monitor input does).

.PARAMETER SourceRoot
    Root folder to search recursively for files to index.

.PARAMETER Index
    Target Splunk index name.

.PARAMETER SourceType
    Sourcetype to assign (e.g. the custom XML sourcetype set up earlier).

.PARAMETER HostSegmentIndex
    1-based segment number of each file's FULL absolute path that contains the
    hostname, when split on '\'. Default: 5.

.PARAMETER FileFilter
    Filter for files to index. Default '*.xml'.

.PARAMETER SplunkBin
    Full path to splunk.exe. Defaults to the standard install location; override if
    yours differs.

.PARAMETER Username
    Optional Splunk username for CLI auth. If provided without -Password, you will
    be prompted securely. If omitted entirely, the script assumes you already have
    an active CLI session (i.e. you ran 'splunk login' beforehand) - which avoids
    passing credentials on the command line at all and is the recommended approach.

.PARAMETER Password
    Optional plaintext password paired with -Username. Prefer omitting both and
    using 'splunk login' first; if you do use this, be aware the credential will
    briefly appear in the child process's command line (visible to other processes
    on the same machine while it runs).

.PARAMETER StateFilePath
    Path to a checkpoint file tracking already-indexed files. Defaults to
    "<SourceRoot>\_splunk_oneshot_state.csv". Delete it to force a full re-index of
    everything, or use -Force for a one-off override without deleting it.

.PARAMETER CsvReportPath
    Path to the run's result report. Defaults to
    "<SourceRoot>\SplunkOneshot_Report_<timestamp>.csv".

.PARAMETER Limit
    Only process the first N matching files. Useful for a quick validation run
    before committing to the full dataset.

.PARAMETER Force
    Re-index files even if the checkpoint file says they were already indexed
    successfully in a prior run.

.EXAMPLE
    # Dry run first - see exactly which host would be derived for each file
    .\Index-XmlToSplunk.ps1 -SourceRoot D:\LOGS_TO_CHECK\FOLDER\ -Index winlogs `
        -SourceType wevtutil_rendered_xml -HostSegmentIndex 4 -WhatIf

.EXAMPLE
    # Quick validation against 2 files only
    .\Index-XmlToSplunk.ps1 -SourceRoot  D:\LOGS_TO_CHECK\FOLDER\ -Index winlogs `
        -SourceType wevtutil_rendered_xml -HostSegmentIndex 4 -Limit 2

.EXAMPLE
    # Full run, assuming 'splunk login' was already run in this shell/session
    .\Index-XmlToSplunk.ps1 -SourceRoot  D:\LOGS_TO_CHECK\FOLDER\ -Index winlogs `
        -SourceType wevtutil_rendered_xml -HostSegmentIndex 4

.NOTES
    - Run 'splunk login' once beforehand (interactively) so the CLI session is
      cached, and you can omit -Username/-Password entirely. This is the safest
      option credential-wise.
    - 'oneshot' indexing is synchronous per file and can take a while for large
      files - there is no incremental progress from the CLI itself, so progress
      here is tracked at the file-count level, not bytes/events.
    - Test with -WhatIf and then -Limit on a couple of files before running against
      an entire multi-host dataset.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$SourceRoot,

    [Parameter(Mandatory)]
    [string]$Index,

    [Parameter(Mandatory)]
    [string]$SourceType,

    [Parameter()]
    [int]$HostSegmentIndex = 5,

    [Parameter()]
    [string]$FileFilter = '*.xml',

    [Parameter()]
    [string]$SplunkBin = 'C:\Program Files\Splunk\bin\splunk.exe',

    [Parameter()]
    [string]$Username,

    [Parameter()]
    [string]$Password,

    [Parameter()]
    [string]$StateFilePath,

    [Parameter()]
    [string]$CsvReportPath,

    [Parameter()]
    [int]$Limit,

    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ---- Resolve dependencies / defaults -----------------------------------------------

if (-not (Test-Path -LiteralPath $SplunkBin -PathType Leaf)) {
    throw "splunk.exe not found at '$SplunkBin'. Pass the correct path via -SplunkBin."
}

if (-not $StateFilePath) {
    $StateFilePath = Join-Path $SourceRoot '_splunk_oneshot_state.csv'
}

if (-not $CsvReportPath) {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $CsvReportPath = Join-Path $SourceRoot "SplunkOneshot_Report_$timestamp.csv"
}

# Build -auth argument if credentials were supplied
$authArg = $null
if ($Username) {
    if (-not $Password) {
        $secure = Read-Host -Prompt "Splunk password for $Username" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    $authArg = "$Username`:$Password"
}

# ---- Load checkpoint state -----------------------------------------------------------

$alreadyIndexed = New-Object 'System.Collections.Generic.HashSet[string]'
if ((Test-Path -LiteralPath $StateFilePath) -and -not $Force) {
    try {
        Import-Csv -LiteralPath $StateFilePath | ForEach-Object {
            if ($_.Status -eq 'Success') { [void]$alreadyIndexed.Add($_.SourceFile) }
        }
        Write-Host "Loaded checkpoint: $($alreadyIndexed.Count) file(s) already indexed previously." -ForegroundColor DarkCyan
    }
    catch {
        Write-Warning "Could not read existing state file '$StateFilePath': $($_.Exception.Message). Treating as empty."
    }
}

# ---- Discover files ---------------------------------------------------------------

$files = Get-ChildItem -LiteralPath $SourceRoot -Filter $FileFilter -File -Recurse
if ($Limit) {
    $files = $files | Select-Object -First $Limit
}

if (-not $files) {
    Write-Warning "No files matching '$FileFilter' found under '$SourceRoot'."
    return
}

Write-Host "Found $($files.Count) file(s) to consider." -ForegroundColor Cyan

$results = [System.Collections.Generic.List[object]]::new()
$total = $files.Count
$counter = 0

foreach ($file in $files) {

    $counter++
    Write-Progress -Activity 'Indexing into Splunk' `
        -Status "$counter / $total : $($file.FullName)" `
        -PercentComplete ([math]::Round(($counter / $total) * 100, 1))

    $segments = $file.FullName -split '\\'
    if ($HostSegmentIndex -lt 1 -or $HostSegmentIndex -gt $segments.Count) {
        Write-Warning "  Segment index $HostSegmentIndex out of range for '$($file.FullName)' ($($segments.Count) segments) - skipping."
        $results.Add([PSCustomObject]@{
            SourceFile = $file.FullName
            Hostname   = $null
            Status     = 'SkippedBadSegmentIndex'
            ExitCode   = $null
            Message    = "Path has $($segments.Count) segments, requested index $HostSegmentIndex"
            Timestamp  = (Get-Date).ToUniversalTime().ToString('o')
        })
        continue
    }
    $hostName = $segments[$HostSegmentIndex - 1]

    if (-not $Force -and $alreadyIndexed.Contains($file.FullName)) {
        Write-Host "  Skipping (already indexed per checkpoint): $($file.FullName)" -ForegroundColor DarkYellow
        $results.Add([PSCustomObject]@{
            SourceFile = $file.FullName
            Hostname   = $hostName
            Status     = 'SkippedAlreadyIndexed'
            ExitCode   = $null
            Message    = ''
            Timestamp  = (Get-Date).ToUniversalTime().ToString('o')
        })
        continue
    }

    Write-Host "  [$counter/$total] host=$hostName  file=$($file.Name)"

    $argList = @(
        'add', 'oneshot'
        ('"{0}"' -f $file.FullName)
        '-index', $Index
        '-sourcetype', $SourceType
        '-hostname', $hostName
    )
    if ($authArg) {
        $argList += @('-auth', $authArg)
    }

    if ($PSCmdlet.ShouldProcess($file.FullName, "splunk add oneshot (index=$Index, sourcetype=$SourceType, host=$hostName)")) {

        $stdOutPath = [System.IO.Path]::GetTempFileName()
        $stdErrPath = [System.IO.Path]::GetTempFileName()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            $proc = Start-Process -FilePath $SplunkBin -ArgumentList $argList `
                -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput $stdOutPath -RedirectStandardError $stdErrPath

            $sw.Stop()
            $stdOut = if (Test-Path $stdOutPath) { Get-Content -LiteralPath $stdOutPath -Raw } else { '' }
            $stdErr = if (Test-Path $stdErrPath) { Get-Content -LiteralPath $stdErrPath -Raw } else { '' }

            if ($proc.ExitCode -eq 0) {
                Write-Host "    OK ($([math]::Round($sw.Elapsed.TotalSeconds,1))s)" -ForegroundColor Green
                $status = 'Success'
                $message = $stdOut.Trim()
            }
            else {
                Write-Warning "    FAILED (exit $($proc.ExitCode)): $stdErr"
                $status = 'Failed'
                $message = "$stdErr $stdOut".Trim()
            }
        }
        catch {
            $sw.Stop()
            Write-Warning "    FAILED (exception): $($_.Exception.Message)"
            $status = 'Failed'
            $message = $_.Exception.Message
        }
        finally {
            Remove-Item -LiteralPath $stdOutPath, $stdErrPath -Force -ErrorAction SilentlyContinue
        }

        $result = [PSCustomObject]@{
            SourceFile   = $file.FullName
            Hostname     = $hostName
            Status       = $status
            ExitCode     = $proc.ExitCode
            Message      = $message
            ElapsedSecs  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            Timestamp    = (Get-Date).ToUniversalTime().ToString('o')
        }
        $results.Add($result)

        # Append to checkpoint immediately (not just at the end) so a crash mid-run
        # doesn't lose track of files already successfully indexed.
        $writeHeader = -not (Test-Path -LiteralPath $StateFilePath)
        $result | Select-Object SourceFile, Hostname, Status, ExitCode, Timestamp |
            Export-Csv -LiteralPath $StateFilePath -NoTypeInformation -Encoding UTF8 -Append:(!$writeHeader)
    }
}

Write-Progress -Activity 'Indexing into Splunk' -Completed

# ---- Final report -------------------------------------------------------------------

$results | Export-Csv -LiteralPath $CsvReportPath -NoTypeInformation -Encoding UTF8

$successCount = ($results | Where-Object Status -eq 'Success').Count
$skipCount    = ($results | Where-Object { $_.Status -like 'Skipped*' }).Count
$failCount    = ($results | Where-Object Status -eq 'Failed').Count

Write-Host ""
Write-Host "Done. $successCount indexed, $skipCount skipped, $failCount failed (of $($results.Count) considered)." -ForegroundColor Green
Write-Host "Report:    $CsvReportPath"
Write-Host "Checkpoint: $StateFilePath"

if ($failCount -gt 0) {
    Write-Warning "$failCount file(s) failed. See '$CsvReportPath' for details (Message column has stderr/stdout)."
}
