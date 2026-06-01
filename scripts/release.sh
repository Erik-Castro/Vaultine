#!/bin/bash
# 🚀 Release v0.2.0-rc1 — Helper Script

set -e

VERSION="v0.2.0-rc1"
COMMIT="3e872665cda0c3d4ff2311bbd6d54a0bb4ecea62"

echo "🚀 Vaultine Release $VERSION"
echo "============================="
echo ""
echo "[1/4] Creating git tag..."
git tag -a "$VERSION" \
  -m "Release Candidate 1: Security hardening & CI/CD" \
  -m "73% of v0.2.0 completed. Ready for beta testing."

echo "✅ Tag created: $VERSION"

echo ""
echo "[2/4] Pushing tag to GitHub..."
git push origin "$VERSION"
echo "✅ Tag pushed"

echo ""
echo "[3/4] Summary"
echo "============"
echo "✅ Release v0.2.0-rc1 created successfully!"
echo ""
echo "📍 Next Steps:"
echo "   1. Go to: https://github.com/Erik-Castro/Vaultine/releases/tag/$VERSION"
echo "   2. Edit and publish the draft release"
echo "   3. Announce in GitHub Discussions"
echo ""
echo "📚 Documentation:"
echo "   - Testing Guide: RELEASE_CANDIDATE.md"
echo "   - Changelog: CHANGELOG.md"
echo "   - Roadmap: ROADMAP.md"
echo ""
