# Control plane image. The build stage holds the toolchain and the whole checkout; the image that runs holds the
# binary, the migrations and the example configuration, and runs as a user without root.
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN ["/usr/local/go/bin/go", "build", "-trimpath", "-ldflags=-s -w", "-o", "/out/wafio", "./cmd/wafio"]

# distroless static: CA certificates and time zones, no shell, user nonroot (65532).
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/wafio /usr/local/bin/wafio
COPY --from=build /src/migrations /app/migrations
COPY --from=build /src/config/config.example.yaml /app/config/config.example.yaml
USER nonroot:nonroot
EXPOSE 9087 9090
ENTRYPOINT ["/usr/local/bin/wafio"]
CMD ["serve", "--migrate"]
