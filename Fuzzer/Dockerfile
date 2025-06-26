FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential clang llvm git cmake ninja-build python3 python3-pip \
      flex bison autoconf automake libtool pkg-config \
      wget curl ca-certificates libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt
ENV FUZZER_HOME=/opt/fuzzers
RUN mkdir -p "$FUZZER_HOME"

COPY Fusion /opt/Fusion

RUN cat > /opt/install_and_patch.sh <<'EOF'
#!/bin/bash
set -euo pipefail
REPO_URL="$1"
DST="$2"
git clone --depth 1 "$REPO_URL" "$DST"
cp -r /opt/Fusion/* "$DST"/
EOF
RUN chmod +x /opt/install_and_patch.sh

RUN /opt/install_and_patch.sh https://github.com/google/AFL.git \
       "$FUZZER_HOME/afl" && \
    make -C "$FUZZER_HOME/afl" -j"$(nproc)"

RUN /opt/install_and_patch.sh https://github.com/puppet-meteor/MOpt-AFL.git \
       "$FUZZER_HOME/mopt-afl" && \
    make -C "$FUZZER_HOME/mopt-afl" -j"$(nproc)"

RUN /opt/install_and_patch.sh https://github.com/AFLplusplus/AFLplusplus.git \
       "$FUZZER_HOME/aflpp" && \
    make -C "$FUZZER_HOME/aflpp" distrib -j"$(nproc)" && \
    make -C "$FUZZER_HOME/aflpp" llvm_mode -j"$(nproc)"

RUN /opt/install_and_patch.sh https://github.com/kupl/SeamFuzz-public.git \
       "$FUZZER_HOME/seamfuzz" && \
    make -C "$FUZZER_HOME/seamfuzz" distrib -j"$(nproc)" && \
    make -C "$FUZZER_HOME/seamfuzz" llvm_mode -j"$(nproc)"

RUN /opt/install_and_patch.sh https://github.com/diewufeihong/SLIME.git \
       "$FUZZER_HOME/slime" && \
    make -C "$FUZZER_HOME/slime" -j"$(nproc)" && \
    make -C "$FUZZER_HOME/slime/llvm_mode" -j"$(nproc)" && \
    make -C "$FUZZER_HOME/slime/llvm_mode_crash" -j"$(nproc)"

ENV PATH="$FUZZER_HOME/afl:$FUZZER_HOME/mopt-afl:$FUZZER_HOME/aflpp:$FUZZER_HOME/seamfuzz:$FUZZER_HOME/slime:$PATH"

WORKDIR /workspace
CMD ["/bin/bash"]
