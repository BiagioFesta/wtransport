use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize;
use criterion::Criterion;
use std::hint::black_box;
use wtransport_proto::datagram::Datagram;
use wtransport_proto::ids::QStreamId;

const QSTREAM_ID: QStreamId = QStreamId::MAX;
const PAYLOAD: &[u8] = b"Payload";

fn bench_datagram(c: &mut Criterion) {
    c.bench_function("read", |b| {
        b.iter_batched_ref(
            || {
                let dgram = Datagram::new(QSTREAM_ID, PAYLOAD);
                let mut buffer = vec![0; dgram.write_size()];
                dgram.write(&mut buffer).unwrap();
                buffer
            },
            |buffer| {
                let _ = black_box(Datagram::read(buffer));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("write", |b| {
        b.iter_batched_ref(
            || {
                let dgram = Datagram::new(QSTREAM_ID, PAYLOAD);
                let buffer = vec![0; dgram.write_size()];
                (dgram, buffer)
            },
            |(dgram, buffer)| dgram.write(buffer),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(datagram, bench_datagram);
criterion_main!(datagram);
