use crate::domain::{Frame, FrameMode, FrameTransaction};
use alloy::primitives::{keccak256, Bytes, B256};
use alloy::rlp::{BufMut, Encodable};

// Frame mode constants
const FRAME_MODE_VERIFY: u8 = 0;
const FRAME_MODE_SENDER: u8 = 1;
const FRAME_MODE_DEFAULT: u8 = 2;

// The transaction type prefix for EIP-8141 Frame Transactions
pub const FRAME_TX_TYPE: u8 = 0x06;

/// Custom Encodable implementation for Frame that optionally elides data for VERIFY frames.
struct EncodableFrame<'a> {
    frame: &'a Frame,
    elide_verify_data: bool,
}

impl<'a> Encodable for EncodableFrame<'a> {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut header = alloy::rlp::Header {
            list: true,
            payload_length: 0,
        };

        let mode_val = match self.frame.mode {
            FrameMode::Verify => FRAME_MODE_VERIFY,
            FrameMode::Sender => FRAME_MODE_SENDER,
            FrameMode::Default => FRAME_MODE_DEFAULT,
        };

        let target_bytes = alloy::hex::decode(&self.frame.target).unwrap_or_default();
        let value_bytes = alloy::hex::decode(&self.frame.value).unwrap_or_default();
        let data_bytes = if self.elide_verify_data && matches!(self.frame.mode, FrameMode::Verify) {
            vec![] // Elide the VERIFY frame data!
        } else {
            alloy::hex::decode(&self.frame.data).unwrap_or_default()
        };

        header.payload_length += mode_val.length();
        header.payload_length += self.frame.flags.length();
        header.payload_length += target_bytes.length();
        header.payload_length += self.frame.gas_limit.length();
        header.payload_length += value_bytes.length();
        header.payload_length += data_bytes.length();

        header.encode(out);
        mode_val.encode(out);
        self.frame.flags.encode(out);
        target_bytes.encode(out);
        self.frame.gas_limit.encode(out);
        value_bytes.encode(out);
        data_bytes.encode(out);
    }

    fn length(&self) -> usize {
        let mut payload_length = 0;

        let mode_val = match self.frame.mode {
            FrameMode::Verify => FRAME_MODE_VERIFY,
            FrameMode::Sender => FRAME_MODE_SENDER,
            FrameMode::Default => FRAME_MODE_DEFAULT,
        };

        let target_bytes = alloy::hex::decode(&self.frame.target).unwrap_or_default();
        let value_bytes = alloy::hex::decode(&self.frame.value).unwrap_or_default();
        let data_bytes = if self.elide_verify_data && matches!(self.frame.mode, FrameMode::Verify) {
            vec![]
        } else {
            alloy::hex::decode(&self.frame.data).unwrap_or_default()
        };

        payload_length += mode_val.length();
        payload_length += self.frame.flags.length();
        payload_length += target_bytes.length();
        payload_length += self.frame.gas_limit.length();
        payload_length += value_bytes.length();
        payload_length += data_bytes.length();

        alloy::rlp::length_of_length(payload_length) + payload_length
    }
}

pub struct Eip8141Encoder;

impl Eip8141Encoder {
    /// Fully encodes the transaction to RLP format, including the 0x06 prefix.
    pub fn encode_transaction(tx: &FrameTransaction) -> Bytes {
        let mut out = vec![FRAME_TX_TYPE];

        let mut header = alloy::rlp::Header {
            list: true,
            payload_length: 0,
        };

        header.payload_length += tx.chain_id.length();
        header.payload_length += tx.nonce_key.length();
        let nonce_seq_val = tx.nonce_seq.unwrap_or(0);
        header.payload_length += nonce_seq_val.length();
        let sender_bytes = alloy::hex::decode(&tx.sender).unwrap_or_default();
        header.payload_length += sender_bytes.length();

        let max_priority_fee_per_gas_val = tx.max_priority_fee_per_gas.unwrap_or(0);
        let max_fee_per_gas_val = tx.max_fee_per_gas.unwrap_or(0);
        header.payload_length += max_priority_fee_per_gas_val.length();
        header.payload_length += max_fee_per_gas_val.length();

        let mut frames_payload_length = 0;
        for frame in &tx.frames {
            let encodable_frame = EncodableFrame {
                frame,
                elide_verify_data: false,
            };
            frames_payload_length += encodable_frame.length();
        }
        let frames_header_len = alloy::rlp::length_of_length(frames_payload_length);
        header.payload_length += frames_header_len + frames_payload_length;

        header.encode(&mut out);
        tx.chain_id.encode(&mut out);
        tx.nonce_key.encode(&mut out);
        nonce_seq_val.encode(&mut out);
        sender_bytes.encode(&mut out);

        let frames_header = alloy::rlp::Header {
            list: true,
            payload_length: frames_payload_length,
        };
        frames_header.encode(&mut out);
        for frame in &tx.frames {
            let encodable_frame = EncodableFrame {
                frame,
                elide_verify_data: false,
            };
            encodable_frame.encode(&mut out);
        }

        max_priority_fee_per_gas_val.encode(&mut out);
        max_fee_per_gas_val.encode(&mut out);

        Bytes::from(out)
    }

    /// Computes the signature hash of the transaction according to EIP-8141/8250,
    /// where VERIFY frame data is explicitly elided.
    pub fn compute_sig_hash(tx: &FrameTransaction) -> B256 {
        let mut rlp_payload = vec![];

        let mut header = alloy::rlp::Header {
            list: true,
            payload_length: 0,
        };

        header.payload_length += tx.chain_id.length();
        header.payload_length += tx.nonce_key.length();
        let nonce_seq_val = tx.nonce_seq.unwrap_or(0);
        header.payload_length += nonce_seq_val.length();
        let sender_bytes = alloy::hex::decode(&tx.sender).unwrap_or_default();
        header.payload_length += sender_bytes.length();

        let max_priority_fee_per_gas_val = tx.max_priority_fee_per_gas.unwrap_or(0);
        let max_fee_per_gas_val = tx.max_fee_per_gas.unwrap_or(0);
        header.payload_length += max_priority_fee_per_gas_val.length();
        header.payload_length += max_fee_per_gas_val.length();

        let mut frames_payload_length = 0;
        for frame in &tx.frames {
            let encodable_frame = EncodableFrame {
                frame,
                elide_verify_data: true,
            };
            frames_payload_length += encodable_frame.length();
        }
        let frames_header_len = alloy::rlp::length_of_length(frames_payload_length);
        header.payload_length += frames_header_len + frames_payload_length;

        header.encode(&mut rlp_payload);
        tx.chain_id.encode(&mut rlp_payload);
        tx.nonce_key.encode(&mut rlp_payload);
        nonce_seq_val.encode(&mut rlp_payload);
        sender_bytes.encode(&mut rlp_payload);

        let frames_header = alloy::rlp::Header {
            list: true,
            payload_length: frames_payload_length,
        };
        frames_header.encode(&mut rlp_payload);
        for frame in &tx.frames {
            let encodable_frame = EncodableFrame {
                frame,
                elide_verify_data: true,
            };
            encodable_frame.encode(&mut rlp_payload);
        }

        max_priority_fee_per_gas_val.encode(&mut rlp_payload);
        max_fee_per_gas_val.encode(&mut rlp_payload);

        let mut hash_payload = vec![FRAME_TX_TYPE];
        hash_payload.extend_from_slice(&rlp_payload);

        keccak256(&hash_payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    fn create_test_tx() -> FrameTransaction {
        FrameTransaction {
            chain_id: 1,
            nonce_key: U256::ZERO,
            nonce_seq: Some(10),
            sender: "0x1111111111111111111111111111111111111111".to_string(),
            max_priority_fee_per_gas: Some(10),
            max_fee_per_gas: Some(20),
            frames: vec![
                Frame {
                    mode: FrameMode::Verify,
                    flags: 0,
                    target: "0x1111111111111111111111111111111111111111".to_string(),
                    gas_limit: 100000,
                    value: "0x".to_string(),
                    data: "0xdeadbeef".to_string(), // User signature
                },
                Frame {
                    mode: FrameMode::Verify,
                    flags: 0,
                    target: "0x2222222222222222222222222222222222222222".to_string(), // Sponsor Paymaster
                    gas_limit: 50000,
                    value: "0x".to_string(),
                    data: "".to_string(), // Empty sponsor signature pre-allocation
                },
            ],
        }
    }

    #[test]
    fn test_sig_hash_elides_verify_data() {
        let mut tx_before = create_test_tx();
        let sig_hash_before = Eip8141Encoder::compute_sig_hash(&tx_before);

        // Inject sponsor data (what the Compiler does)
        tx_before.frames[1].data = "0x1234567890abcdef".to_string();

        let sig_hash_after = Eip8141Encoder::compute_sig_hash(&tx_before);

        // The hash should be perfectly identical because the data fields are elided!
        assert_eq!(sig_hash_before, sig_hash_after);
    }

    #[test]
    fn test_encode_transaction_includes_prefix() {
        let tx = create_test_tx();
        let encoded = Eip8141Encoder::encode_transaction(&tx);
        
        // EIP-8141 defines FRAME_TX_TYPE as 0x06
        assert_eq!(encoded[0], 0x06);
        
        // Ensure it's successfully encoded into multiple bytes
        assert!(encoded.len() > 10);
    }
}
