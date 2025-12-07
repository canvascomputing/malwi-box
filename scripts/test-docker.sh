#!/bin/bash
set -e

PYTHON_VERSIONS=("3.10" "3.11" "3.12" "3.13")

# Parse arguments
RUN_ALL=true
SPECIFIC_VERSION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --python)
            SPECIFIC_VERSION="$2"
            RUN_ALL=false
            shift 2
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        *)
            echo "Usage: $0 [--python VERSION] [--parallel]"
            exit 1
            ;;
    esac
done

if [ "$RUN_ALL" = true ]; then
    if [ "$PARALLEL" = true ]; then
        docker compose -f docker-compose.test.yml build --no-cache
        docker compose -f docker-compose.test.yml up --abort-on-container-exit
    else
        for version in "${PYTHON_VERSIONS[@]}"; do
            echo "=========================================="
            echo "Testing Python $version"
            echo "=========================================="
            docker compose -f docker-compose.test.yml build --no-cache "test-py${version//./}"
            docker compose -f docker-compose.test.yml run --rm "test-py${version//./}"
        done
    fi
else
    echo "Testing Python $SPECIFIC_VERSION"
    docker compose -f docker-compose.test.yml build --no-cache "test-py${SPECIFIC_VERSION//./}"
    docker compose -f docker-compose.test.yml run --rm "test-py${SPECIFIC_VERSION//./}"
fi

echo "All tests passed!"
