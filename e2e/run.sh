#!/usr/bin/env bash
# End-to-end matrix: every implementation (PHP, Rust, Go, Node.js) issues tokens, and every
# implementation judges the tokens of every issuer. A judge's verdicts and fields are compared
# with what the tokens should give, so one wrong implementation shows up as a row or a column.
#
#   e2e/run.sh [directory that holds laravel-rust-encryption, laravel-go-encryption, laravel-node-encryption]
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
libs=${1:-$(dirname "$here")}
rust=$libs/laravel-rust-encryption
go=$libs/laravel-go-encryption
node=$libs/laravel-node-encryption
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

issue() { # <implementation>
  case $1 in
    php)  php "$here/bin/emit-tokens.php" ;;
    rust) (cd "$rust" && cargo run -q --example envelope) ;;
    go)   (cd "$go" && go run ./cmd/envelope) ;;
    node) (cd "$node" && node scripts/envelope.js) ;;
  esac
}

judge() { # <implementation>, tokens on stdin
  case $1 in
    php)  php "$here/bin/judge.php" ;;
    rust) (cd "$rust" && cargo run -q --example envelope_judge) ;;
    go)   (cd "$go" && go run ./cmd/envelope-judge) ;;
    node) (cd "$node" && node scripts/envelope-judge.js) ;;
  esac
}

impls="php rust go node"

echo "== fixture copies"
php "$here/e2e/check-fixtures.php" "$rust/fixtures/envelope-vectors.json" "$go/fixtures/envelope-vectors.json" "$node/fixtures/envelope-vectors.json"

echo "== issuing"
for i in $impls; do
  issue "$i" > "$work/issued-$i.json"
  echo "   $i: $(wc -c < "$work/issued-$i.json") bytes"
done

echo "== matrix (issuer -> judge)"
failed=0
for i in $impls; do
  for j in $impls; do
    judge "$j" < "$work/issued-$i.json" > "$work/judged-$j-$i.json"
    php "$here/e2e/compare.php" "$work/issued-$i.json" "$work/judged-$j-$i.json" "$i -> $j" || failed=1
  done
done

if [ "$failed" -ne 0 ]; then
  echo "end-to-end matrix FAILED" >&2
  exit 1
fi
echo "end-to-end matrix passed"
