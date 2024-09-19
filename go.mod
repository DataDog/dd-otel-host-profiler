module github.com/DataDog/dd-opentelemetry-profiler

go 1.23.1

require (
	github.com/DataDog/zstd v1.5.6
	github.com/cilium/ebpf v0.15.0
	github.com/elastic/go-freelru v0.13.0
	github.com/google/pprof v0.0.0-20240829160300-da1f7e9f2b25
	github.com/jsimonetti/rtnetlink v1.4.2
	github.com/open-telemetry/opentelemetry-ebpf-profiler v0.0.0-20240918090752-0a8979a41728
	github.com/peterbourgon/ff/v3 v3.4.0
	github.com/sirupsen/logrus v1.9.3
	github.com/tklauser/numcpus v0.8.0
	github.com/zeebo/xxh3 v1.0.2
	golang.org/x/sys v0.21.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/elastic/go-perf v0.0.0-20191212140718-9c656876f595 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.20.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	go.opentelemetry.io/otel v1.27.0 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	golang.org/x/arch v0.8.0 // indirect
	golang.org/x/exp v0.0.0-20240613232115-7f521ea00fb8 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240513163218-0867130af1f8 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240513163218-0867130af1f8 // indirect
	google.golang.org/grpc v1.64.1 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
)

// To update the Datadog/opentelemetry-ebpf-profiler dependency on latest commit on datadog branch, change the following line to:
// replace github.com/open-telemetry/opentelemetry-ebpf-profiler => github.com/DataDog/opentelemetry-ebpf-profiler datadog
// and run `GOPRIVATE=github.com/Datadog/* go mod tidy`
replace github.com/open-telemetry/opentelemetry-ebpf-profiler => github.com/DataDog/opentelemetry-ebpf-profiler v0.0.0-20240919140712-bacfde8003b0
