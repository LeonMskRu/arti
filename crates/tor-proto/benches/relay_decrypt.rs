use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::prelude::*;

#[cfg(feature = "counter-galois-onion")]
use aes::{Aes128, Aes256};
use tor_bytes::SecretBuf;
use tor_llcrypto::{
    cipher::aes::{Aes128Ctr, Aes256Ctr},
    d::{Sha1, Sha3_256},
};
#[cfg(feature = "counter-galois-onion")]
use tor_proto::bench_utils::cgo;
use tor_proto::bench_utils::{tor1, OutboundClientCryptWrapper, RelayBody, RelayCryptState};

mod cpu_time;
use cpu_time::*;

const HOP_NUM: u8 = 1;

/// Helper macro to set up a relay decryption benchmark.
macro_rules! relay_decrypt_setup {
    ($client_state_construct: path, $relay_state_construct: path) => {{
        let seed1: SecretBuf = b"hidden we are free".to_vec().into();
        let seed2: SecretBuf = b"free to speak, to free ourselves".to_vec().into();

        // No need to simulate other relays since we are only one relay.
        let relay_state = $relay_state_construct(seed1.clone()).unwrap();

        let mut cc_out = OutboundClientCryptWrapper::new();
        let state1 = $client_state_construct(seed1).unwrap();
        cc_out.add_layer(state1);
        // Add a second layer to avoid the benched relay to recognize the relay cell.
        let state2 = $client_state_construct(seed2).unwrap();
        cc_out.add_layer(state2);

        let mut rng = rand::rng();
        let mut cell = [0u8; 509];
        rng.fill(&mut cell[..]);
        let mut cell: RelayBody = cell.into();
        cc_out.encrypt(&mut cell, HOP_NUM).unwrap();
        (cell, relay_state)
    }};
}

/// Benchmark a relay decrypting a relay cell coming from the client.
pub fn relay_decrypt_benchmark(c: &mut Criterion<CpuTime>) {
    let mut group = c.benchmark_group("relay_decrypt");
    group.throughput(Throughput::Bytes(509));

    group.bench_function("Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                relay_decrypt_setup!(
                    tor1::Tor1ClientCryptState::<Aes128Ctr, Sha1>::construct,
                    tor1::Tor1RelayCryptState::<Aes128Ctr, Sha1>::construct
                )
            },
            |(cell, relay_state)| {
                relay_state.decrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                relay_decrypt_setup!(
                    tor1::Tor1ClientCryptState::<Aes256Ctr, Sha3_256>::construct,
                    tor1::Tor1RelayCryptState::<Aes256Ctr, Sha3_256>::construct
                )
            },
            |(cell, relay_state)| {
                relay_state.decrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    #[cfg(feature = "counter-galois-onion")]
    group.bench_function("CGO_Aes128", |b| {
        b.iter_batched_ref(
            || {
                relay_decrypt_setup!(
                    cgo::CgoClientCryptState::<Aes128, Aes128>::construct,
                    cgo::CgoRelayCryptSate::<Aes128, Aes128>::construct
                )
            },
            |(cell, relay_state)| {
                relay_state.decrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    #[cfg(feature = "counter-galois-onion")]
    group.bench_function("CGO_Aes256", |b| {
        b.iter_batched_ref(
            || {
                relay_decrypt_setup!(
                    cgo::CgoClientCryptState::<Aes256, Aes256>::construct,
                    cgo::CgoRelayCryptSate::<Aes256, Aes256>::construct
                )
            },
            |(cell, relay_state)| {
                relay_state.decrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    name = relay_decrypt;
    config = Criterion::default()
       .with_measurement(CpuTime)
       .sample_size(5000);
    targets = relay_decrypt_benchmark);
criterion_main!(relay_decrypt);
