#!/bin/bash
# 🚀 Release v0.3.1-beta — Helper Script

set -e

VERSION="v0.3.1-beta"

echo "🚀 Vaultine Release $VERSION"
echo "============================="
echo ""
echo "[1/4] Creating git tag..."
git tag -a "$VERSION" \
  -m "Release v0.3.1-beta: 33 optimizations — bugs, performance, quality, build" \
  -m "182/182 tests. Backup format v2 (breaking)."

echo "✅ Tag created: $VERSION"

echo ""
echo "[2/4] Pushing tag to GitHub..."
git push origin "$VERSION"
echo "✅ Tag pushed"

echo ""
echo "[3/4] Creating source tarball..."
git archive --format=tar.gz -o "vaultine-${VERSION}.tar.gz" "$VERSION"
echo "✅ Tarball created: vaultine-${VERSION}.tar.gz"

echo ""
echo "[4/4] Summary"
echo "============"
echo "✅ Release $VERSION created and pushed!"
echo ""
echo "📍 Next Steps:"
echo "   1. Go to: https://github.com/Erik-Castro/Vaultine/releases/tag/$VERSION"
echo "   2. Upload vaultine-${VERSION}.tar.gz"
echo "   3. Publish the release"
echo "   4. Announce in GitHub Discussions"
echo ""
echo "📚 Documentation:"
echo "   - Testing Guide: RELEASE_CANDIDATE.md"
echo "   - Changelog: CHANGELOG.md"
echo "   - Roadmap: ROADMAP.md"
