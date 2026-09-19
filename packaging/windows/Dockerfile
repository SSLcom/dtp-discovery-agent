# The image that builds the Windows installer.
#
# PINNED BY DIGEST, for the same reason as the nfpm image in
# script/build-packages.sh: this produces something a customer installs as an
# administrator, so what the base image contains must not be something a third
# party can change under us. The two tools are pinned by version as well —
# Debian 12 is frozen, so these resolve for the life of the release, and if one
# ever stops resolving the build fails loudly here instead of quietly producing
# an installer built by a version nobody chose.
#
# wixl is NOT the WiX Toolset: it is msitools' reimplementation of a subset.
# That subset is why this builds on Linux at all, and packaging/windows/dtp-agent.wxs
# notes the two things it cannot do.
FROM debian:12-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      wixl=0.101+repack-1 \
      msitools=0.101+repack-1 \
 && rm -rf /var/lib/apt/lists/*
