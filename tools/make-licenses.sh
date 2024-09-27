#!/usr/bin/env bash
set -euo pipefail


TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/make-licenses.XXXXXX")
trap "rm -rf ${TMPDIR}" EXIT ERR TERM

GOBIN="${TMPDIR}/bin" $(go env GOROOT)/bin/go install github.com/google/go-licenses/v2@v2.0.0-alpha.1

"$TMPDIR/bin/go-licenses" save --save_path "${TMPDIR}/sources"  ./...
"$TMPDIR/bin/go-licenses" report ./... --template ./tools/licenses.tpl > "LICENSE-3rdparty.csv" 2> "${TMPDIR}/errors" || (cat "${TMPDIR}/errors" >&2 && exit -1)

$(go env GOROOT)/bin/go run ./tools/merge-licenses-copyrights.go -fixes ./tools/copyrights_fixes.csv -licenses "${TMPDIR}/sources" -output "LICENSE-3rdparty.csv" "LICENSE-3rdparty.csv"

cat ./tools/non-go-dependencies.csv >> "LICENSE-3rdparty.csv"
