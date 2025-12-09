#!/bin/bash
# Bump version in pyproject.toml and uv.lock, commit, and tag
set -e

get_current_version() {
    grep 'version = "' pyproject.toml | head -1 | sed 's/.*version = "\([^"]*\)".*/\1/'
}

compute_new_version() {
    local current="$1"
    local major minor patch
    IFS='.' read -r major minor patch <<< "$current"
    echo "$major.$minor.$((patch + 1))"
}

update_pyproject() {
    local current="$1"
    local new="$2"
    sed -i '' "s/version = \"$current\"/version = \"$new\"/" pyproject.toml
}

update_lockfile() {
    uv lock
}

commit_and_tag() {
    local version="$1"
    git add pyproject.toml uv.lock
    git commit -m "bump version to $version"
    git tag "$version"
}

main() {
    local current new

    current=$(get_current_version)
    echo "Current version: $current"

    new=$(compute_new_version "$current")
    echo "New version: $new"

    update_pyproject "$current" "$new"
    update_lockfile
    commit_and_tag "$new"

    echo "Done! Created tag $new"
}

main
