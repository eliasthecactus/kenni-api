# ============ build ============
FROM swift:6.2-noble AS build
WORKDIR /build

COPY Package.swift Package.resolved* ./
RUN swift package resolve

COPY Sources ./Sources
COPY Tests ./Tests
ARG SWIFT_BUILD_JOBS=2
RUN mkdir /staging
RUN --mount=type=cache,target=/build/.build,sharing=locked \
    swift build --quiet -c release --product App --static-swift-stdlib \
        --jobs "${SWIFT_BUILD_JOBS}" \
    && cp "$(swift build -c release --show-bin-path)/App" /staging/App

# ============ run ============
FROM ubuntu:noble
RUN apt-get -qq update && apt-get -qq -y install ca-certificates tzdata libcurl4 curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --create-home vapor
WORKDIR /app
COPY --from=build --chown=vapor:vapor /staging/App /app/App
# /app must stay writable for the SQLite dev fallback (no DATABASE_URL set).
RUN chown vapor:vapor /app
USER vapor

ENV ENV=production
EXPOSE 8080
ENTRYPOINT ["/app/App"]
CMD ["serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "8080"]
