//! DyberVPN Cryptographic Benchmarks
//!
//! Run with: cargo bench --package dybervpn-protocol

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use dybervpn_protocol::{select_backend, CryptoBackend};

fn bench_mlkem_keygen(c: &mut Criterion) {
    let backend = select_backend();
    
    c.bench_function("ML-KEM-768 keygen", |b| {
        b.iter(|| {
            black_box(backend.mlkem_keygen().unwrap())
        })
    });
}

fn bench_mlkem_encaps(c: &mut Criterion) {
    let backend = select_backend();
    let (pk, _sk) = backend.mlkem_keygen().unwrap();
    
    c.bench_function("ML-KEM-768 encapsulate", |b| {
        b.iter(|| {
            black_box(backend.mlkem_encaps(&pk).unwrap())
        })
    });
}

fn bench_mlkem_decaps(c: &mut Criterion) {
    let backend = select_backend();
    let (pk, sk) = backend.mlkem_keygen().unwrap();
    let (ct, _ss) = backend.mlkem_encaps(&pk).unwrap();
    
    c.bench_function("ML-KEM-768 decapsulate", |b| {
        b.iter(|| {
            black_box(backend.mlkem_decaps(&sk, &ct).unwrap())
        })
    });
}

fn bench_x25519_keygen(c: &mut Criterion) {
    let backend = select_backend();
    
    c.bench_function("X25519 keygen", |b| {
        b.iter(|| {
            black_box(backend.x25519_keygen().unwrap())
        })
    });
}

fn bench_x25519_dh(c: &mut Criterion) {
    let backend = select_backend();
    let (pk, sk) = backend.x25519_keygen().unwrap();
    
    c.bench_function("X25519 Diffie-Hellman", |b| {
        b.iter(|| {
            black_box(backend.x25519_diffie_hellman(&sk, &pk).unwrap())
        })
    });
}

fn bench_ed25519_sign(c: &mut Criterion) {
    let backend = select_backend();
    let (_pk, sk) = backend.ed25519_keygen().unwrap();
    let msg = b"Test message for benchmarking Ed25519 signatures in DyberVPN";
    
    c.bench_function("Ed25519 sign", |b| {
        b.iter(|| {
            black_box(backend.ed25519_sign(&sk, msg).unwrap())
        })
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let backend = select_backend();
    let (pk, sk) = backend.ed25519_keygen().unwrap();
    let msg = b"Test message for benchmarking Ed25519 signatures in DyberVPN";
    let sig = backend.ed25519_sign(&sk, msg).unwrap();
    
    c.bench_function("Ed25519 verify", |b| {
        b.iter(|| {
            black_box(backend.ed25519_verify(&pk, msg, &sig).unwrap())
        })
    });
}

fn bench_hybrid_handshake(c: &mut Criterion) {
    let backend = select_backend();
    
    c.bench_function("Hybrid handshake (initiator)", |b| {
        b.iter(|| {
            // Initiator side of handshake
            let (mlkem_pk, _mlkem_sk) = backend.mlkem_keygen().unwrap();
            let (x25519_pk, x25519_sk) = backend.x25519_keygen().unwrap();
            
            // Simulate receiving responder's ephemeral
            let (resp_x25519_pk, _) = backend.x25519_keygen().unwrap();
            let (ct, mlkem_ss) = backend.mlkem_encaps(&mlkem_pk).unwrap();
            let x25519_ss = backend.x25519_diffie_hellman(&x25519_sk, &resp_x25519_pk).unwrap();
            
            // Combine
            let _combined = backend.combine_shared_secrets(&mlkem_ss, &x25519_ss, b"handshake").unwrap();
            
            black_box((ct, x25519_pk))
        })
    });
}

fn bench_hkdf(c: &mut Criterion) {
    let backend = select_backend();
    let ikm = [0u8; 32];
    let salt = b"DyberVPN";
    let info = b"key derivation";
    
    let mut group = c.benchmark_group("HKDF-SHA256");
    
    for size in [32, 64, 128].iter() {
        group.bench_with_input(BenchmarkId::new("output_size", size), size, |b, &size| {
            let mut output = vec![0u8; size];
            b.iter(|| {
                backend.hkdf_sha256(salt, &ikm, info, &mut output).unwrap();
                black_box(&output)
            })
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_mlkem_keygen,
    bench_mlkem_encaps,
    bench_mlkem_decaps,
    bench_x25519_keygen,
    bench_x25519_dh,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_hybrid_handshake,
    bench_hkdf,
);

criterion_main!(benches);
