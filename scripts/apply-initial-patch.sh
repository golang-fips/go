#!/bin/bash

set -ex

# Apply the initial patch. This patch is basic and shouldn't accrue many
# conflicts over time so it should be safe to apply.
git apply -v ../patches/000-initial-setup.patch
# Add the initial changes to the index so the later diff ignores them.
git add .
git commit -m phase1
