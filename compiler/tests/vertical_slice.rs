use alloy::primitives::{Address, Bytes, B256, address};
use open_engine_core::domain::{Frame, FrameMode, FrameTransaction};
use open_engine_core::gateway::{ChainGateway, GatewayError};
use open_engine_core::signer::{InMemorySigner, Signer};
use compiler::FrameCompiler;
use broadcaster::MempoolBroadcaster;
use queue::{DurableExecution, job::BorrowedJob};
use std::sync::Arc;
use std::future::Future;

/// A simple mock gateway for testing vertical slices.
struct MockGateway {
    nonce: u64,
    gas_limit: u64,
    tx_hash: B256,
}

impl ChainGateway for MockGateway {
    fn get_transaction_count(&self, _address: Address) -> impl Future<Output = Result<u64, GatewayError>> + Send {
        async move { Ok(self.nonce) }
    }

    fn estimate_gas(&self, _tx: &FrameTransaction) -> impl Future<Output = Result<u64, GatewayError>> + Send {
        async move { Ok(self.gas_limit) }
    }

    fn send_raw_transaction(&self, _bytes: Bytes) -> impl Future<Output = Result<B256, GatewayError>> + Send {
        async move { Ok(self.tx_hash) }
    }
}

#[tokio::test]
async fn test_self_relay_vertical_slice() {
    // 1. Setup
    let gateway = Arc::new(MockGateway {
        nonce: 42,
        gas_limit: 21000,
        tx_hash: B256::repeat_byte(0xaa),
    });
    
    // Use a dummy key for the sponsor signer
    let sponsor_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let sponsor_signer = Arc::new(InMemorySigner::new(sponsor_key).unwrap());

    let compiler = FrameCompiler::new(gateway.clone(), sponsor_signer.clone());
    let broadcaster = MempoolBroadcaster::new(gateway.clone(), sponsor_signer.clone());

    // 2. Create a Self-Relay Transaction
    let sender = address!("1111111111111111111111111111111111111111");
    let tx = FrameTransaction {
        chain_id: 1,
        nonce_key: alloy::primitives::U256::ZERO,
        nonce_seq: None, // Broadcaster will resolve this
        sender: sender.to_string(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0,
                target: sender.to_string(), // Self-relay
                gas_limit: 100000,
                value: "0".to_string(),
                data: "0xsignature".to_string(),
            },
            Frame {
                mode: FrameMode::Sender,
                flags: 0,
                target: "0x2222222222222222222222222222222222222222".to_string(),
                gas_limit: 50000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
        ],
    };

    // 3. Step 1: Compilation
    let compiled_tx = compiler.compile_and_validate(tx).await.expect("Compilation failed");
    assert_eq!(compiled_tx.sender, sender.to_string());
    
    // 4. Step 2: Queueing (Simulated by passing the Job)
    let job = queue::job::Job {
        id: "test-job".to_string(),
        data: compiled_tx,
        attempts: 0,
        created_at: 0,
        processed_at: None,
        finished_at: None,
    };
    let borrowed_job = queue::job::BorrowedJob::new(job, "test-lease".to_string());

    // 5. Step 3: Broadcasting
    let result = broadcaster.process(&borrowed_job).await;
    
    assert!(result.is_ok(), "Broadcasting failed: {:?}", result.err());
    let tx_hash = result.unwrap();
    
    // Verify the tx hash matches our mock
    assert_eq!(tx_hash, B256::repeat_byte(0xaa).to_string());
    
    println!("Vertical slice successful! Tx Hash: {}", tx_hash);
}

#[tokio::test]
async fn test_sponsor_vertical_slice() {
    // 1. Setup
    let gateway = Arc::new(MockGateway {
        nonce: 100,
        gas_limit: 50000,
        tx_hash: B256::repeat_byte(0xbb),
    });
    
    // The Compiler's key (acts as Paymaster sponsor)
    let sponsor_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let sponsor_signer = Arc::new(InMemorySigner::new(sponsor_key).unwrap());

    let compiler = FrameCompiler::new(gateway.clone(), sponsor_signer.clone());
    let broadcaster = MempoolBroadcaster::new(gateway.clone(), sponsor_signer.clone());

    // 2. Create a Sponsored Transaction
    let sender = address!("1111111111111111111111111111111111111111");
    let paymaster = address!("9999999999999999999999999999999999999999");
    
    let tx = FrameTransaction {
        chain_id: 1,
        nonce_key: alloy::primitives::U256::ZERO,
        nonce_seq: None,
        sender: sender.to_string(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0,
                target: sender.to_string(), // User's verify
                gas_limit: 100000,
                value: "0".to_string(),
                data: "0xuser_sig".to_string(),
            },
            Frame {
                mode: FrameMode::Verify,
                flags: 0,
                target: paymaster.to_string(), // Sponsor's verify
                gas_limit: 100000,
                value: "0".to_string(),
                data: "".to_string(), // Empty, compiler will fill this
            },
            Frame {
                mode: FrameMode::Sender,
                flags: 0,
                target: "0x2222222222222222222222222222222222222222".to_string(),
                gas_limit: 50000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
        ],
    };

    // 3. Step 1: Compilation (Injects signature)
    let compiled_tx = compiler.compile_and_validate(tx).await.expect("Compilation failed");
    
    // Verify that the sponsor frame (index 1) now has a signature
    assert!(!compiled_tx.frames[1].data.is_empty(), "Sponsor signature was not injected");
    println!("Injected signature: {}", compiled_tx.frames[1].data);
    
    // 4. Step 2: Queueing
    let job = queue::job::Job {
        id: "test-job-sponsored".to_string(),
        data: compiled_tx,
        attempts: 0,
        created_at: 0,
        processed_at: None,
        finished_at: None,
    };
    let borrowed_job = queue::job::BorrowedJob::new(job, "test-lease-sponsored".to_string());

    // 5. Step 3: Broadcasting
    let result = broadcaster.process(&borrowed_job).await;
    
    assert!(result.is_ok(), "Broadcasting failed: {:?}", result.err());
    let tx_hash = result.unwrap();
    
    assert_eq!(tx_hash, B256::repeat_byte(0xbb).to_string());
    println!("Sponsor vertical slice successful! Tx Hash: {}", tx_hash);
}
