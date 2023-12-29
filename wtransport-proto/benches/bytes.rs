use criterion::async_executor::FuturesExecutor;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;

const BUFFER: &[u8; 8] = &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];

fn get_varint(c: &mut Criterion) {
    let mut get_varint = c.benchmark_group("get_varint");

    get_varint.bench_function("sync", |b| {
        b.iter(|| {
            use wtransport_proto::bytes::BytesReader;
            BUFFER.as_slice().get_varint()
        })
    });

    get_varint.bench_function("async", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            use wtransport_proto::bytes::BytesReaderAsync;
            BUFFER.as_slice().get_varint().await
        })
    });

    get_varint.finish();
}

fn get_bytes(c: &mut Criterion) {
    let mut get_bytes = c.benchmark_group("get_bytes");

    get_bytes.bench_function("sync", |b| {
        b.iter(|| {
            use wtransport_proto::bytes::BytesReader;
            BUFFER.as_slice().get_bytes(8)
        })
    });

    get_bytes.bench_function("async", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            use wtransport_proto::bytes::BytesReaderAsync;
            let mut output = [0; 8];
            BUFFER.as_slice().get_buffer(&mut output).await
        })
    });

    get_bytes.finish();
}

fn bench_bytes(c: &mut Criterion) {
    get_varint(c);
    get_bytes(c);
}

criterion_group!(bytes, bench_bytes);
criterion_main!(bytes);
