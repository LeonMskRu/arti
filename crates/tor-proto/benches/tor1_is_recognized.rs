use criterion::{criterion_group, criterion_main, Criterion};
use digest::Digest;
use rand::prelude::*;

use tor_cell::relaycell::msg::SendmeTag;
use tor_llcrypto::d::{Sha1, Sha3_256};
use tor_proto::bench_utils::{
    tor1::{is_recognized, set_digest},
    RelayBody,
};

mod cpu_time;
use cpu_time::*;

/// Create a random inbound cell with the digest computed.
fn create_digested_cell<D: Digest + Clone>(rng: &mut ThreadRng, d: &mut D) -> RelayBody {
    let mut cell = [0u8; 509];
    rng.fill(&mut cell[..]);
    let mut cell: RelayBody = cell.into();
    let mut used_digest = SendmeTag::from([0_u8; 20]);

    set_digest::<_>(&mut cell, d, &mut used_digest);

    cell
}

/// Benchmark the `client_decrypt` function.
pub fn tor1_is_recognized_benchmark(c: &mut Criterion<CpuTime>) {
    let mut group = c.benchmark_group("tor1_is_recognized");
    group.throughput(criterion::Throughput::Bytes(509));

    group.bench_function("Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::rng();
                let mut d = Sha1::new();

                let cell = create_digested_cell::<_>(&mut rng, &mut d);
                (cell, Sha1::new(), SendmeTag::from([0_u8; 20]))
            },
            |(cell, d, rcvd)| {
                is_recognized::<_>(cell, d, rcvd);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::rng();
                let mut d = Sha3_256::new();

                let cell = create_digested_cell::<_>(&mut rng, &mut d);
                (cell, Sha3_256::new(), SendmeTag::from([0_u8; 20]))
            },
            |(cell, d, rcvd)| {
                is_recognized::<_>(cell, d, rcvd);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
   name = tor1_is_recognized;
   config = Criterion::default()
      .with_measurement(CpuTime)
      .sample_size(5000);
   targets = tor1_is_recognized_benchmark);
criterion_main!(tor1_is_recognized);
