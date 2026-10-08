FROM golang:1.26.8-bookworm@sha256:26de5cf8eac40c12a1ff8de1a634971b4654fd881225eed7ace643b8c769f2f5 AS go-build
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src/service
COPY service/ ./
RUN --network=none test "$(go version)" = 'go version go1.26.8 linux/amd64' && \
    go test -mod=vendor ./internal/supervisor ./internal/processguard && \
    go build -mod=vendor -trimpath -buildvcs=false -o /out/judge-service ./cmd/judge-service && \
    go build -mod=vendor -trimpath -buildvcs=false -o /out/startrack-judger ./cmd/startrack-judger && \
    go build -mod=vendor -trimpath -buildvcs=false -o /out/supervisor ./cmd/startrack-supervisor && \
    go build -mod=vendor -trimpath -buildvcs=false -o /out/runtime-init ./cmd/startrack-runtime-init && \
    go build -mod=vendor -trimpath -buildvcs=false -o /out/judge-migrate ./cmd/judge-migrate && \
    go build -mod=vendor -trimpath -buildvcs=false -o /out/judge-admin ./cmd/judge-admin && \
    go build -mod=vendor -trimpath -buildvcs=false -o /out/judge-outbox ./cmd/judge-outbox && \
    go build -mod=vendor -trimpath -buildvcs=false -o /out/startrack-runtime-matrix ./cmd/startrack-runtime-matrix && \
    go build -mod=vendor -trimpath -buildvcs=false -o /out/startrack-import-capacity ./cmd/startrack-import-capacity
WORKDIR /src/go-judge
COPY upstream/go-judge/ ./
RUN --network=none go build -mod=vendor -trimpath -buildvcs=false -o /out/go-judge ./cmd/go-judge

FROM python:3.11.15-bookworm@sha256:eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8 AS native-build
COPY upstream/problemtools/ /src/problemtools/
COPY service/internal/runtime/native/checker-launcher.cc /src/checker-launcher.cc
RUN --network=none test "$(g++ --version | head -n 1)" = 'g++ (Debian 12.2.0-14+deb12u1) 12.2.0' && \
    test "$(/usr/local/bin/python3 --version)" = 'Python 3.11.15' && \
    mkdir -p /out && \
    g++ -O3 -o /out/default_validator /src/problemtools/support/default_validator/default_validator.cc && \
    g++ -std=c++17 -O2 -o /out/startrack-checker-launcher /src/checker-launcher.cc

FROM python:3.11.15-bookworm@sha256:eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8
COPY --from=go-build /out/ /usr/local/libexec/startrack/
COPY --from=go-build /out/startrack-runtime-matrix /opt/startrack/bin/startrack-runtime-matrix
COPY --from=go-build /out/startrack-import-capacity /opt/startrack/bin/startrack-import-capacity
COPY --from=native-build /out/default_validator /opt/startrack/libexec/default_validator
COPY --from=native-build /out/startrack-checker-launcher /usr/local/bin/startrack-checker-launcher
COPY upstream/problemtools/support/default_grader/default_grader /opt/startrack/libexec/default_grader
COPY service/scripts/problemtools-bridge.py /opt/startrack/libexec/problemtools-bridge.py
COPY upstream/problemtools/tests/default_validator_tests/ /opt/startrack/qualification/default_validator_tests/
COPY legal/ /opt/startrack/legal/
COPY provenance/ /opt/startrack/provenance/
COPY docker/mount.yaml /opt/startrack/mount.yaml
COPY docker/image.lock.json /opt/startrack/image.lock.json
COPY docker/security-profile.lock.json /opt/startrack/security-profile.lock.json
COPY docker/startrack-v02.seccomp.json /opt/startrack/startrack-v02.seccomp.json
COPY docker/startrack-v02.apparmor /opt/startrack/startrack-v02.apparmor
COPY docker/startrack-workload-seccomp.yaml /opt/startrack/startrack-workload-seccomp.yaml
COPY docker/workload-security-profile.lock.json /opt/startrack/workload-security-profile.lock.json
COPY service/migrations/ /opt/startrack/migrations/
COPY service/scripts/validation-tools.py /build/validation-tools.py
COPY service/scripts/problemtools-wheel-audit.py /build/problemtools-wheel-audit.py
COPY validation-tools/ /build/validation-tools/
COPY upstream/problemtools/ /build/problemtools/
RUN --network=none /usr/local/bin/python3 /build/validation-tools.py install \
    --lock /opt/startrack/provenance/validation-tools.lock.json \
    --legal-root /opt/startrack/legal --bundle /build/validation-tools && \
    cp /build/validation-tools/installed-inventory.json /opt/startrack/provenance/validation-tools-installed.json && \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PROBLEMTOOLS=1.20260907 /usr/local/bin/python3 -m pip wheel \
    --no-build-isolation --no-deps --no-index --wheel-dir /build/dist /build/problemtools && \
    /usr/local/bin/python3 -m pip install --disable-pip-version-check --no-index --no-deps /build/dist/problemtools-1.20260907-*.whl && \
    sha256sum /build/dist/problemtools-1.20260907-*.whl > /opt/startrack/provenance/problemtools-wheel.sha256 && \
    /usr/local/bin/python3 /build/problemtools-wheel-audit.py \
    --wheel /build/dist/problemtools-1.20260907-py3-none-any.whl \
    --output /opt/startrack/provenance/problemtools-wheel-audit.json && \
    /usr/local/bin/python3 -m pip check && \
    /usr/local/bin/python3 -m pip list --format=json > /opt/startrack/provenance/python-packages.json && \
    rm -rf /build /root/.cache
RUN mkdir -p /run/secrets/startrack /var/lib/startrack/private /var/lib/startrack-judger \
    /run/startrack-api /run/startrack-judger /run/startrack-supervisor /run/startrack && \
    chmod 0755 /opt/startrack/libexec/default_grader && \
    sha256sum /opt/startrack/libexec/* /opt/startrack/bin/* /usr/local/bin/startrack-checker-launcher \
    /usr/local/libexec/startrack/* > /opt/startrack/provenance/binaries.sha256 && \
    dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /opt/startrack/provenance/os-packages.tsv
WORKDIR /
ENTRYPOINT ["/usr/local/libexec/startrack/supervisor"]
