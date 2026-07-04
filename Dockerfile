# ============ build ============
FROM swift:6.2-noble AS build
WORKDIR /build

COPY Package.swift Package.resolved* ./
RUN swift package resolve

COPY Sources ./Sources
COPY Tests ./Tests
RUN swift build -c release --product App --static-swift-stdlib

# ============ run ============
FROM ubuntu:noble
RUN apt-get -qq update && apt-get -qq -y install ca-certificates tzdata libcurl4 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --create-home vapor
WORKDIR /app
COPY --from=build --chown=vapor:vapor /build/.build/release/App /app/App
# /app must stay writable for the SQLite dev fallback (no DATABASE_URL set).
RUN chown vapor:vapor /app
USER vapor

ENV ENV=production
EXPOSE 8080
ENTRYPOINT ["/app/App"]
CMD ["serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "8080"]
