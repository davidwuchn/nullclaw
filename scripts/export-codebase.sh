#!/usr/bin/env sh
set -eu

usage() {
    cat <<'USAGE'
Usage: scripts/export-codebase.sh [options]

Build a single-file, review-friendly nullclaw source bundle.

Options:
  -o, --output PATH       Write bundle to PATH (default: nullclaw-codebase.md)
      --repo PATH         Export from another git checkout
      --include-vendor   Include vendor/ sources that are skipped by default
  -h, --help              Show this help

The export is based on git-tracked files, so local build output, caches,
secrets, and ignored files are not included.
USAGE
}

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

repo_arg=""
output_arg=""
include_vendor=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|--output)
            [ "$#" -ge 2 ] || die "missing value for $1"
            output_arg=$2
            shift 2
            ;;
        --repo)
            [ "$#" -ge 2 ] || die "missing value for --repo"
            repo_arg=$2
            shift 2
            ;;
        --include-vendor)
            include_vendor=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

if [ -n "$repo_arg" ]; then
    repo_root=$(cd "$repo_arg" && pwd -P)
else
    repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git checkout"
fi

git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not a git checkout: $repo_root"

if [ -n "$output_arg" ]; then
    case "$output_arg" in
        /*) output_path=$output_arg ;;
        *) output_path=$(pwd -P)/$output_arg ;;
    esac
else
    output_path=$repo_root/nullclaw-codebase.md
fi

output_dir=$(dirname "$output_path")
mkdir -p "$output_dir"

output_rel=""
case "$output_path" in
    "$repo_root"/*) output_rel=${output_path#"$repo_root"/} ;;
esac

tmp_manifest=$(mktemp "${TMPDIR:-/tmp}/nullclaw-codebase-manifest.XXXXXX")
tmp_output=$(mktemp "${TMPDIR:-/tmp}/nullclaw-codebase-output.XXXXXX")

cleanup() {
    rm -f "$tmp_manifest" "$tmp_output"
}
trap cleanup EXIT HUP INT TERM

should_include() {
    path=$1

    [ -n "$output_rel" ] && [ "$path" = "$output_rel" ] && return 1

    case "$path" in
        zig-out/*|zig-cache/*|.zig-cache/*|zig-pkg/*|reference/*)
            return 1
            ;;
        nullclaw-codebase.md)
            return 1
            ;;
        *.png|*.jpg|*.jpeg|*.gif|*.webp|*.ico|*.pdf|*.db|*.db-journal|*.a|*.o|*.wasm)
            return 1
            ;;
    esac

    if [ "$include_vendor" -eq 0 ]; then
        case "$path" in
            vendor/*) return 1 ;;
        esac
    fi

    case "$path" in
        src/*|docs/*|examples/*|spec/*|scripts/*|.github/*|.githooks/*)
            return 0
            ;;
        vendor/*)
            [ "$include_vendor" -eq 1 ] && return 0
            return 1
            ;;
        AGENTS.md|CLAUDE.md|README.md|CONTRIBUTING.md|SECURITY.md|SIGNAL.md|RELEASING.md|LICENSE)
            return 0
            ;;
        build.zig|build.zig.zon|build.zig.zon2json-lock|config.example.json|Dockerfile)
            return 0
            ;;
        docker-compose.yml|docker-compose.signal.yml|flake.nix|flake.lock|run)
            return 0
            ;;
        .dockerignore|.env.example|.envrc|.gitignore)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

git -C "$repo_root" ls-files | while IFS= read -r path; do
    if should_include "$path"; then
        printf '%s\n' "$path"
    fi
done > "$tmp_manifest"

file_count=$(wc -l < "$tmp_manifest" | tr -d ' ')
total_bytes=0
while IFS= read -r path; do
    bytes=$(wc -c < "$repo_root/$path" | tr -d ' ')
    total_bytes=$((total_bytes + bytes))
done < "$tmp_manifest"

commit=$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || printf 'unknown')
generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

{
    printf '# nullclaw Codebase Bundle\n\n'
    printf 'Generated: %s\n' "$generated_at"
    printf 'Commit: %s\n' "$commit"
    printf 'Files: %s\n' "$file_count"
    printf 'Source bytes: %s\n\n' "$total_bytes"
    printf 'This bundle includes git-tracked source, docs, examples, specs, CI, and root project configuration.\n'
    printf 'It skips generated output, local caches, ignored files, binary assets, and vendored dependencies by default.\n\n'
    printf '## File Index\n\n'
    while IFS= read -r path; do
        bytes=$(wc -c < "$repo_root/$path" | tr -d ' ')
        printf -- '- `%s` (%s bytes)\n' "$path" "$bytes"
    done < "$tmp_manifest"
    printf '\n## File Contents\n\n'
    while IFS= read -r path; do
        printf '<<<BEGIN_FILE: %s>>>\n' "$path"
        cat "$repo_root/$path"
        last_char=$(tail -c 1 "$repo_root/$path" 2>/dev/null || printf '\n')
        [ "$last_char" = "" ] || printf '\n'
        printf '<<<END_FILE: %s>>>\n\n' "$path"
    done < "$tmp_manifest"
} > "$tmp_output"

mv "$tmp_output" "$output_path"
printf 'Wrote %s files (%s source bytes) to %s\n' "$file_count" "$total_bytes" "$output_path"
