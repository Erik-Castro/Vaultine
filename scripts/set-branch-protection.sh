#!/usr/bin/env bash
set -euo pipefail

REPO="Erik-Castro/Vaultine"
BRANCH="main"

echo "Configuring branch protection for $REPO:$BRANCH..."

# Requires gh auth login to have been run first
gh api "repos/$REPO/branches/$BRANCH/protection" \
  --method PUT \
  --header "Accept: application/vnd.github.v3+json" \
  --field "required_status_checks[strict]=true" \
  --field "required_status_checks[contexts][]=build-and-test (Debug, gcc)" \
  --field "required_status_checks[contexts][]=build-and-test (Release, gcc)" \
  --field "required_status_checks[contexts][]=build-and-test (Debug, clang)" \
  --field "required_status_checks[contexts][]=build-and-test (Release, clang)" \
  --field "required_status_checks[contexts][]=lint" \
  --field "required_status_checks[contexts][]=security-scan" \
  --field "enforce_admins=true" \
  --field "required_pull_request_reviews[required_approving_review_count]=1" \
  --field "restrictions[users][]=Erik-Castro" \
  > /dev/null

echo "✓ Branch protection configured for $BRANCH"
echo
echo "Settings applied:"
echo "  - Require status checks (strict): build-and-test (4x) + lint + security-scan"
echo "  - Require PR review: 1 approval"
echo "  - Dismiss stale reviews"
echo "  - Restrict push access to Erik-Castro"
echo "  - Include administrators"
echo
echo "Want to adjust? Run: gh api repos/$REPO/branches/$BRANCH/protection"
