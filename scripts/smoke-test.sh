#!/bin/bash
set -e

echo "==> Version"
OUTPUT=$(vet --version)
echo "$OUTPUT"
[[ "$OUTPUT" =~ ^vet\ [0-9]+\.[0-9]+\.[0-9]+ ]] || { echo "Invalid version"; exit 1; }

echo "==> Pattern count"
COUNT=$(vet patterns | grep -oE '^[0-9]+ patterns' | grep -oE '[0-9]+')
echo "Patterns: $COUNT"
[ "$COUNT" -ge 90 ] || { echo "Expected 90+"; exit 1; }

echo "==> Detect Stripe key"
echo 'key = "sk_live_51NzKDwH3JxMvRtYbUcE8q"' > /tmp/test.txt
vet scan /tmp --format json | grep -q "stripe" || { echo "Failed"; exit 1; }
rm /tmp/test.txt

echo "==> Exit non-zero on findings"
echo 'AKIAIOSFODNN7EXAMPLE' > /tmp/test.txt
! vet scan /tmp > /dev/null 2>&1 || { echo "Should exit non-zero"; exit 1; }
rm /tmp/test.txt

echo "==> Exit zero when clean"
mkdir -p /tmp/clean-test
echo '# readme' > /tmp/clean-test/README.md
vet scan /tmp/clean-test || { echo "Should exit zero"; exit 1; }
rm -rf /tmp/clean-test

echo "==> SARIF output"
echo 'sk_live_51NzKDwH3JxMvRtYbUcE8q' > /tmp/test.txt
vet scan /tmp --format sarif 2>/dev/null | grep -q 'schema' || { echo "Invalid SARIF"; exit 1; }
rm /tmp/test.txt

echo "✓ All checks passed"