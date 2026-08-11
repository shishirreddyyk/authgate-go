FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/authgate ./cmd/authgate

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/authgate /authgate
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/authgate"]
