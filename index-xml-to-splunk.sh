#!/usr/bin/env bash
#
# index-xml-to-splunk.sh
#
# Recursively finds converted event-log XML files under a root folder and indexes
# each one into Splunk via 'splunk add oneshot', deriving the hostname from a
# specific segment of each file's full path.
#
# Mirrors the behaviour of the PowerShell version (Index-XmlToSplunk.ps1) for
# Linux Splunk hosts.
#
# Expects a layout like:
#     /home/you/xmldata/HOST01/Security.xml
#     /home/you/xmldata/HOST01/Application.xml
#     /home/you/xmldata/HOST02/Security.xml
#
# For a full path such as /home/you/xmldata/HOST01/Security.xml, splitting on
# '/' (after stripping the leading slash) gives segments (1-based):
#     1: home
#     2: you
#     3: xmldata
#     4: HOST01
#     5: Security.xml
#
# --host-segment tells the script which 1-based segment is the hostname. Run
# with --dry-run first and check the printed host= values before doing a real
# run - the right number depends on how deep your source root sits.
#
# IMPORTANT: 'splunk add oneshot' has no built-in de-duplication (unlike a
# monitor input's fishbucket tracking) - running it twice on the same file
# indexes it twice. This script keeps a local checkpoint file recording
# successfully indexed files, and skips them on re-runs unless --force is
# given.
#
# Requires bash 4.4+ (for `mapfile -d ''`).
#
# ---------------------------------------------------------------------------
# USAGE
#   ./index-xml-to-splunk.sh --source-root DIR --index NAME --sourcetype NAME
#                             [--host-segment N] [--file-filter GLOB]
#                             [--splunk-bin PATH] [--username USER] [--password PASS]
#                             [--state-file PATH] [--report-file PATH]
#                             [--limit N] [--force] [--dry-run]
#
# EXAMPLES
#   # Dry run - confirm derived hostnames before doing anything real
#   ./index-xml-to-splunk.sh --source-root /home/you/xmldata --index winlogs \
#       --sourcetype wevtutil_rendered_xml --host-segment 5 --dry-run
#
#   # Validate against 2 files
#   ./index-xml-to-splunk.sh --source-root /home/you/xmldata --index winlogs \
#       --sourcetype wevtutil_rendered_xml --host-segment 5 --limit 2
#
#   # Full run (recommended: run `splunk login` first so no credentials are
#   # ever passed on this script's command line)
#   /opt/splunk/bin/splunk login
#   ./index-xml-to-splunk.sh --source-root /home/you/xmldata --index winlogs \
#       --sourcetype wevtutil_rendered_xml --host-segment 5
# ---------------------------------------------------------------------------

set -uo pipefail

# ---- Defaults -----------------------------------------------------------------------

SOURCE_ROOT=""
INDEX=""
SOURCETYPE=""
HOST_SEGMENT=5
FILE_FILTER="*.xml"
SPLUNK_BIN="/opt/splunk/bin/splunk"
USERNAME=""
PASSWORD=""
STATE_FILE=""
REPORT_FILE=""
LIMIT=0
FORCE=0
DRY_RUN=0

usage() {
    grep '^#' "$0" | sed -e 's/^# \{0,1\}//' -e '/^!\/usr\/bin\/env/d'
    exit 1
}

# ---- Parse arguments ------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-root)   SOURCE_ROOT="$2"; shift 2 ;;
        --index)         INDEX="$2"; shift 2 ;;
        --sourcetype)    SOURCETYPE="$2"; shift 2 ;;
        --host-segment)  HOST_SEGMENT="$2"; shift 2 ;;
        --file-filter)   FILE_FILTER="$2"; shift 2 ;;
        --splunk-bin)    SPLUNK_BIN="$2"; shift 2 ;;
        --username)      USERNAME="$2"; shift 2 ;;
        --password)      PASSWORD="$2"; shift 2 ;;
        --state-file)    STATE_FILE="$2"; shift 2 ;;
        --report-file)   REPORT_FILE="$2"; shift 2 ;;
        --limit)         LIMIT="$2"; shift 2 ;;
        --force)         FORCE=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

if [[ -z "$SOURCE_ROOT" || -z "$INDEX" || -z "$SOURCETYPE" ]]; then
    echo "ERROR: --source-root, --index, and --sourcetype are required." >&2
    usage
fi

if [[ ! -d "$SOURCE_ROOT" ]]; then
    echo "ERROR: --source-root '$SOURCE_ROOT' is not a directory." >&2
    exit 1
fi

if [[ ! -x "$SPLUNK_BIN" ]]; then
    echo "ERROR: splunk binary not found or not executable at '$SPLUNK_BIN'. Use --splunk-bin to specify the correct path." >&2
    exit 1
fi

SOURCE_ROOT="${SOURCE_ROOT%/}"   # strip trailing slash for consistent path math

: "${STATE_FILE:=${SOURCE_ROOT}/_splunk_oneshot_state.tsv}"
: "${REPORT_FILE:=${SOURCE_ROOT}/splunk_oneshot_report_$(date +%Y%m%d_%H%M%S).tsv}"

AUTH_ARG=()
if [[ -n "$USERNAME" ]]; then
    if [[ -z "$PASSWORD" ]]; then
        read -r -s -p "Splunk password for $USERNAME: " PASSWORD
        echo
    fi
    AUTH_ARG=(-auth "${USERNAME}:${PASSWORD}")
fi

# ---- Load checkpoint state ------------------------------------------------------------

declare -A ALREADY_INDEXED
if [[ -f "$STATE_FILE" && "$FORCE" -eq 0 ]]; then
    while IFS=$'\t' read -r c_file c_host c_status c_ts; do
        [[ "$c_status" == "Success" ]] && ALREADY_INDEXED["$c_file"]=1
    done < "$STATE_FILE"
    echo "Loaded checkpoint: ${#ALREADY_INDEXED[@]} file(s) already indexed previously."
fi

# ---- Discover files ---------------------------------------------------------------------

mapfile -d '' FILES < <(find "$SOURCE_ROOT" -type f -iname "$FILE_FILTER" -print0 | sort -z)

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "No files matching '$FILE_FILTER' found under '$SOURCE_ROOT'."
    exit 0
fi

if [[ "$LIMIT" -gt 0 && "$LIMIT" -lt ${#FILES[@]} ]]; then
    FILES=("${FILES[@]:0:$LIMIT}")
fi

TOTAL=${#FILES[@]}
echo "Found $TOTAL file(s) to consider."

# Prepare report/state files with headers if new
[[ -f "$REPORT_FILE" ]] || printf 'SourceFile\tHostname\tStatus\tExitCode\tMessage\tElapsedSecs\tTimestamp\n' > "$REPORT_FILE"
[[ -f "$STATE_FILE"  ]] || printf 'SourceFile\tHostname\tStatus\tTimestamp\n' > "$STATE_FILE"

SUCCESS_COUNT=0
SKIP_COUNT=0
FAIL_COUNT=0
COUNTER=0

sanitize() {
    # Collapse tabs/newlines so a field never breaks the TSV structure
    tr '\t\n\r' '   ' <<< "$1"
}

for FILE in "${FILES[@]}"; do
    COUNTER=$((COUNTER + 1))
    PCT=$(( COUNTER * 100 / TOTAL ))

    # Derive hostname from the requested path segment (1-based, leading '/' stripped)
    RELATIVE="${FILE#/}"
    IFS='/' read -r -a SEGMENTS <<< "$RELATIVE"
    SEG_COUNT=${#SEGMENTS[@]}

    if [[ "$HOST_SEGMENT" -lt 1 || "$HOST_SEGMENT" -gt "$SEG_COUNT" ]]; then
        echo "[$COUNTER/$TOTAL] ($PCT%) WARN: segment $HOST_SEGMENT out of range for '$FILE' ($SEG_COUNT segments) - skipping."
        MSG=$(sanitize "Path has $SEG_COUNT segments, requested index $HOST_SEGMENT")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$FILE" "" "SkippedBadSegmentIndex" "" "$MSG" "0" "$(date -u +%FT%TZ)" >> "$REPORT_FILE"
        continue
    fi
    HOSTNAME_VAL="${SEGMENTS[$((HOST_SEGMENT - 1))]}"

    if [[ "$FORCE" -eq 0 && -n "${ALREADY_INDEXED[$FILE]:-}" ]]; then
        echo "[$COUNTER/$TOTAL] ($PCT%) Skipping (already indexed): $FILE"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$FILE" "$HOSTNAME_VAL" "SkippedAlreadyIndexed" "" "" "0" "$(date -u +%FT%TZ)" >> "$REPORT_FILE"
        continue
    fi

    echo "[$COUNTER/$TOTAL] ($PCT%) host=$HOSTNAME_VAL file=$FILE"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        continue
    fi

    START_TS=$(date +%s.%N)
    OUT=$("$SPLUNK_BIN" add oneshot "$FILE" -index "$INDEX" -sourcetype "$SOURCETYPE" -hostname "$HOSTNAME_VAL" "${AUTH_ARG[@]}" 2>&1)
    EXIT_CODE=$?
    END_TS=$(date +%s.%N)
    ELAPSED=$(awk -v a="$START_TS" -v b="$END_TS" 'BEGIN{printf "%.1f", b-a}')

    if [[ $EXIT_CODE -eq 0 ]]; then
        echo "    OK (${ELAPSED}s)"
        STATUS="Success"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "    FAILED (exit $EXIT_CODE): $OUT" >&2
        STATUS="Failed"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    MSG=$(sanitize "$OUT")
    TS=$(date -u +%FT%TZ)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$FILE" "$HOSTNAME_VAL" "$STATUS" "$EXIT_CODE" "$MSG" "$ELAPSED" "$TS" >> "$REPORT_FILE"
    printf '%s\t%s\t%s\t%s\n' "$FILE" "$HOSTNAME_VAL" "$STATUS" "$TS" >> "$STATE_FILE"
done

echo ""
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "Dry run complete. $TOTAL file(s) considered, nothing was indexed."
else
    echo "Done. $SUCCESS_COUNT indexed, $SKIP_COUNT skipped, $FAIL_COUNT failed (of $TOTAL considered)."
fi
echo "Report:     $REPORT_FILE"
echo "Checkpoint: $STATE_FILE"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "WARNING: $FAIL_COUNT file(s) failed. See '$REPORT_FILE' (Message column) for details." >&2
fi
