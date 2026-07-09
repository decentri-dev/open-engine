use crate::domain::{Frame, FrameMode, FrameSignature, FrameTransaction, RecentRootReference};
use alloy::primitives::{keccak256, Bytes, B256, U256};
use alloy::rlp::{BufMut, Encodable};
use thiserror::Error;

/// A field that cannot be encoded faithfully on the wire.
///
/// The RLP `Encodable` impls cannot fail, so malformed hex/numeric strings
/// would otherwise be silently encoded as empty bytes or zero — signing and
/// broadcasting something the client never intended. Every pipeline entry
/// point must run [`Eip8141Encoder::validate_wire_format`] before the
/// transaction is signed, hashed, or encoded.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct WireFormatError(String);

// Frame mode constants
const FRAME_MODE_DEFAULT: u8 = 0;
const FRAME_MODE_VERIFY: u8 = 1;
const FRAME_MODE_SENDER: u8 = 2;

// The transaction type prefix for EIP-8141 Frame Transactions
pub const FRAME_TX_TYPE: u8 = 0x06;

impl Encodable for Frame {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut header = alloy::rlp::Header {
            list: true,
            payload_length: 0,
        };

        let mode_val = match self.mode {
            FrameMode::Verify => FRAME_MODE_VERIFY,
            FrameMode::Sender => FRAME_MODE_SENDER,
            FrameMode::Default => FRAME_MODE_DEFAULT,
        };

        let target_bytes = self
            .target
            .as_ref()
            .map(|target| decode_hex_bytes(target))
            .unwrap_or_default();
        let value = parse_u256_value(&self.value);
        let data_bytes = decode_hex_bytes(&self.data);

        header.payload_length += mode_val.length();
        header.payload_length += self.flags.length();
        header.payload_length += target_bytes.as_slice().length();
        header.payload_length += self.gas_limit.length();
        header.payload_length += value.length();
        header.payload_length += data_bytes.as_slice().length();

        header.encode(out);
        mode_val.encode(out);
        self.flags.encode(out);
        target_bytes.as_slice().encode(out);
        self.gas_limit.encode(out);
        value.encode(out);
        data_bytes.as_slice().encode(out);
    }

    fn length(&self) -> usize {
        let mut payload_length = 0;

        let mode_val = match self.mode {
            FrameMode::Verify => FRAME_MODE_VERIFY,
            FrameMode::Sender => FRAME_MODE_SENDER,
            FrameMode::Default => FRAME_MODE_DEFAULT,
        };

        let target_bytes = self
            .target
            .as_ref()
            .map(|target| decode_hex_bytes(target))
            .unwrap_or_default();
        let value = parse_u256_value(&self.value);
        let data_bytes = decode_hex_bytes(&self.data);

        payload_length += mode_val.length();
        payload_length += self.flags.length();
        payload_length += target_bytes.as_slice().length();
        payload_length += self.gas_limit.length();
        payload_length += value.length();
        payload_length += data_bytes.as_slice().length();

        alloy::rlp::length_of_length(payload_length) + payload_length
    }
}

impl Encodable for RecentRootReference {
    fn encode(&self, out: &mut dyn BufMut) {
        let header = alloy::rlp::Header {
            list: true,
            payload_length: self.source_id.length() + self.slot.length() + self.root.length(),
        };
        header.encode(out);
        self.source_id.encode(out);
        self.slot.encode(out);
        self.root.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.source_id.length() + self.slot.length() + self.root.length();
        alloy::rlp::length_of_length(payload_length) + payload_length
    }
}

struct EncodableSignature<'a> {
    sig: &'a FrameSignature,
    elide_signature: bool,
}

impl<'a> Encodable for EncodableSignature<'a> {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut header = alloy::rlp::Header {
            list: true,
            payload_length: 0,
        };

        let signer_bytes = decode_hex_bytes(&self.sig.signer);
        let msg_bytes = decode_hex_bytes(&self.sig.msg);
        let sig_bytes = if self.elide_signature && self.sig.msg.is_empty() {
            vec![]
        } else {
            decode_hex_bytes(&self.sig.signature)
        };

        header.payload_length += self.sig.scheme.length();
        header.payload_length += signer_bytes.as_slice().length();
        header.payload_length += msg_bytes.as_slice().length();
        header.payload_length += sig_bytes.as_slice().length();

        header.encode(out);
        self.sig.scheme.encode(out);
        signer_bytes.as_slice().encode(out);
        msg_bytes.as_slice().encode(out);
        sig_bytes.as_slice().encode(out);
    }

    fn length(&self) -> usize {
        let mut payload_length = 0;

        let signer_bytes = decode_hex_bytes(&self.sig.signer);
        let msg_bytes = decode_hex_bytes(&self.sig.msg);
        let sig_bytes = if self.elide_signature && self.sig.msg.is_empty() {
            vec![]
        } else {
            decode_hex_bytes(&self.sig.signature)
        };

        payload_length += self.sig.scheme.length();
        payload_length += signer_bytes.as_slice().length();
        payload_length += msg_bytes.as_slice().length();
        payload_length += sig_bytes.as_slice().length();

        alloy::rlp::length_of_length(payload_length) + payload_length
    }
}

pub struct Eip8141Encoder;

impl Eip8141Encoder {
    /// Verifies every string-typed field encodes faithfully: valid hex where
    /// hex is expected, correct byte widths for addresses/digests, and
    /// parseable numeric values. Rejecting here is what keeps the infallible
    /// `Encodable` impls honest — their `unwrap_or_default` fallbacks become
    /// unreachable for validated transactions.
    pub fn validate_wire_format(tx: &FrameTransaction) -> Result<(), WireFormatError> {
        expect_hex_bytes("sender", &tx.sender, Some(20))?;

        for (i, frame) in tx.frames.iter().enumerate() {
            // An absent/empty target resolves to the sender at execution time.
            if let Some(target) = frame.target.as_deref() {
                if !target.is_empty() && target != "0x" {
                    expect_hex_bytes(&format!("frames[{i}].target"), target, Some(20))?;
                }
            }
            expect_hex_bytes(&format!("frames[{i}].data"), &frame.data, None)?;
            expect_u256(&format!("frames[{i}].value"), &frame.value)?;
        }

        for (i, sig) in tx.signatures.iter().enumerate() {
            expect_hex_bytes(&format!("signatures[{i}].signer"), &sig.signer, Some(20))?;
            // Empty msg means "signed over the canonical sig hash"; otherwise
            // it must be an explicit 32-byte digest.
            if !sig.msg.is_empty() && sig.msg != "0x" {
                expect_hex_bytes(&format!("signatures[{i}].msg"), &sig.msg, Some(32))?;
            }
            // Empty is a valid placeholder (filled by sponsor injection).
            expect_hex_bytes(&format!("signatures[{i}].signature"), &sig.signature, None)?;
        }

        Ok(())
    }

    /// Calculates the gas cost of a byte array according to EIP-7623 / EIP-2028 rules.
    /// Non-zero bytes cost 16 gas, zero bytes cost 4 gas.
    pub fn calldata_cost(data: &[u8]) -> u64 {
        data.iter()
            .map(|&byte| if byte == 0 { 4 } else { 16 })
            .sum()
    }

    pub fn encode_transaction(tx: &FrameTransaction) -> Bytes {
        let mut out = vec![FRAME_TX_TYPE];
        Self::encode_payload(tx, false, &mut out);
        Bytes::from(out)
    }

    /// Encodes the list of frames into RLP bytes.
    pub fn encode_frames(frames: &[Frame]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut payload_length = 0;
        for frame in frames {
            payload_length += frame.length();
        }
        let header = alloy::rlp::Header {
            list: true,
            payload_length,
        };
        header.encode(&mut out);
        for frame in frames {
            frame.encode(&mut out);
        }
        out
    }

    /// Encodes the list of recent-root references into RLP bytes (as an RLP
    /// list), matching the envelope encoding so calldata-gas accounting agrees
    /// with the node.
    pub fn encode_recent_root_references(refs: &[RecentRootReference]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut payload_length = 0;
        for reference in refs {
            payload_length += reference.length();
        }
        let header = alloy::rlp::Header {
            list: true,
            payload_length,
        };
        header.encode(&mut out);
        for reference in refs {
            reference.encode(&mut out);
        }
        out
    }

    /// Encodes the list of signatures into RLP bytes.
    pub fn encode_signatures(signatures: &[FrameSignature]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut payload_length = 0;
        for sig in signatures {
            let encodable_sig = EncodableSignature {
                sig,
                elide_signature: false,
            };
            payload_length += encodable_sig.length();
        }
        let header = alloy::rlp::Header {
            list: true,
            payload_length,
        };
        header.encode(&mut out);
        for sig in signatures {
            let encodable_sig = EncodableSignature {
                sig,
                elide_signature: false,
            };
            encodable_sig.encode(&mut out);
        }
        out
    }

    pub fn compute_sig_hash(tx: &FrameTransaction) -> B256 {
        let mut rlp_payload = vec![];
        Self::encode_payload(tx, true, &mut rlp_payload);

        let mut hash_payload = vec![FRAME_TX_TYPE];
        hash_payload.extend_from_slice(&rlp_payload);

        keccak256(&hash_payload)
    }

    fn encode_payload(tx: &FrameTransaction, elide_signatures: bool, out: &mut Vec<u8>) {
        let mut header = alloy::rlp::Header {
            list: true,
            payload_length: 0,
        };

        header.payload_length += tx.chain_id.length();
        let nonce_keys = tx.effective_nonce_keys();
        let nonce_seq_val = tx.nonce_seq.unwrap_or(0);
        let mut nonce_keys_payload_length = 0;
        for key in &nonce_keys {
            nonce_keys_payload_length += key.length();
        }
        header.payload_length +=
            alloy::rlp::length_of_length(nonce_keys_payload_length) + nonce_keys_payload_length;
        header.payload_length += nonce_seq_val.length();
        let sender_bytes = decode_hex_bytes(&tx.sender);
        header.payload_length += sender_bytes.as_slice().length();

        let max_priority_fee_per_gas_val = tx.max_priority_fee_per_gas.unwrap_or(0);
        let max_fee_per_gas_val = tx.max_fee_per_gas.unwrap_or(0);
        let max_fee_per_blob_gas_val = tx.max_fee_per_blob_gas.unwrap_or_default();
        header.payload_length += max_priority_fee_per_gas_val.length();
        header.payload_length += max_fee_per_gas_val.length();
        header.payload_length += max_fee_per_blob_gas_val.length();
        header.payload_length += tx.blob_versioned_hashes.length();
        header.payload_length += tx.recent_root_references.length();

        let mut frames_payload_length = 0;
        for frame in &tx.frames {
            frames_payload_length += frame.length();
        }
        let frames_header_len = alloy::rlp::length_of_length(frames_payload_length);
        header.payload_length += frames_header_len + frames_payload_length;

        let mut signatures_payload_length = 0;
        for sig in &tx.signatures {
            let encodable_sig = EncodableSignature {
                sig,
                elide_signature: elide_signatures,
            };
            signatures_payload_length += encodable_sig.length();
        }
        let signatures_header_len = alloy::rlp::length_of_length(signatures_payload_length);
        header.payload_length += signatures_header_len + signatures_payload_length;

        header.encode(out);
        tx.chain_id.encode(out);
        let nonce_keys_header = alloy::rlp::Header {
            list: true,
            payload_length: nonce_keys_payload_length,
        };
        nonce_keys_header.encode(out);
        for key in &nonce_keys {
            key.encode(out);
        }
        nonce_seq_val.encode(out);
        sender_bytes.as_slice().encode(out);

        let frames_header = alloy::rlp::Header {
            list: true,
            payload_length: frames_payload_length,
        };
        frames_header.encode(out);
        for frame in &tx.frames {
            frame.encode(out);
        }

        let signatures_header = alloy::rlp::Header {
            list: true,
            payload_length: signatures_payload_length,
        };
        signatures_header.encode(out);
        for sig in &tx.signatures {
            let encodable_sig = EncodableSignature {
                sig,
                elide_signature: elide_signatures,
            };
            encodable_sig.encode(out);
        }

        max_priority_fee_per_gas_val.encode(out);
        max_fee_per_gas_val.encode(out);
        max_fee_per_blob_gas_val.encode(out);
        tx.blob_versioned_hashes.encode(out);
        // EIP-8272: recent-root references close the envelope. Covered by the
        // canonical signature hash (encoded verbatim on both paths).
        tx.recent_root_references.encode(out);
    }
}

/// Strict counterpart of `decode_hex_bytes`: the value must be valid hex
/// (optionally `0x`-prefixed) and, when `expected_len` is given, decode to
/// exactly that many bytes. Empty input is only accepted when no width is
/// required.
fn expect_hex_bytes(
    field: &str,
    value: &str,
    expected_len: Option<usize>,
) -> Result<Vec<u8>, WireFormatError> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let bytes = alloy::hex::decode(stripped)
        .map_err(|e| WireFormatError(format!("{field} is not valid hex: {e}")))?;
    if let Some(expected) = expected_len {
        if bytes.len() != expected {
            return Err(WireFormatError(format!(
                "{field} must be {expected} bytes, got {}",
                bytes.len()
            )));
        }
    }
    Ok(bytes)
}

/// Strict counterpart of `parse_u256_value`: empty means zero, otherwise the
/// value must parse as `0x`-hex (max 32 bytes) or decimal.
fn expect_u256(field: &str, value: &str) -> Result<U256, WireFormatError> {
    let value = value.trim();
    if value.is_empty() || value == "0x" {
        return Ok(U256::ZERO);
    }
    if let Some(hex) = value.strip_prefix("0x") {
        let bytes = alloy::hex::decode(hex)
            .map_err(|e| WireFormatError(format!("{field} is not valid hex: {e}")))?;
        if bytes.len() > 32 {
            return Err(WireFormatError(format!(
                "{field} exceeds 32 bytes ({} bytes)",
                bytes.len()
            )));
        }
        return Ok(U256::from_be_slice(&bytes));
    }
    value
        .parse::<U256>()
        .map_err(|e| WireFormatError(format!("{field} is not a valid decimal value: {e}")))
}

fn decode_hex_bytes(value: &str) -> Vec<u8> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() {
        return Vec::new();
    }
    alloy::hex::decode(value).unwrap_or_default()
}

fn parse_u256_value(value: &str) -> U256 {
    let value = value.trim();
    if value.is_empty() {
        return U256::ZERO;
    }
    if let Some(hex) = value.strip_prefix("0x") {
        let bytes = alloy::hex::decode(hex).unwrap_or_default();
        return U256::from_be_slice(&bytes);
    }
    value.parse::<U256>().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn create_test_tx() -> FrameTransaction {
        FrameTransaction {
            chain_id: 1,
            nonce_keys: vec![U256::ZERO],
            nonce_seq: Some(10),
            sender: "0x1111111111111111111111111111111111111111".to_string(),
            max_priority_fee_per_gas: Some(10),
            max_fee_per_gas: Some(20),
            max_fee_per_blob_gas: Some(U256::ZERO),
            blob_versioned_hashes: vec![],
            recent_root_references: vec![],
            frames: vec![Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Some("0x1111111111111111111111111111111111111111".to_string()),
                gas_limit: 100000,
                value: "0x".to_string(),
                data: "0xdeadbeef".to_string(),
            }],
            signatures: vec![FrameSignature {
                scheme: 0,
                signer: "0x1111111111111111111111111111111111111111".to_string(),
                msg: "".to_string(),
                signature: "0x1234".to_string(),
            }],
        }
    }

    #[test]
    fn sig_hash_elides_signature_bytes() {
        let mut tx_before = create_test_tx();
        let sig_hash_before = Eip8141Encoder::compute_sig_hash(&tx_before);

        // Inject signature bytes (what the Compiler does)
        tx_before.signatures[0].signature = "0x1234567890abcdef".to_string();

        let sig_hash_after = Eip8141Encoder::compute_sig_hash(&tx_before);

        // The hash should be perfectly identical because the signature bytes are elided!
        assert_eq!(sig_hash_before, sig_hash_after);
    }

    #[test]
    fn wire_format_accepts_valid_tx() {
        let tx = create_test_tx();
        assert!(Eip8141Encoder::validate_wire_format(&tx).is_ok());
    }

    #[test]
    fn wire_format_rejects_malformed_fields() {
        // Invalid hex in frame data must not silently encode as empty bytes.
        let mut tx = create_test_tx();
        tx.frames[0].data = "0xsignature".to_string();
        let err = Eip8141Encoder::validate_wire_format(&tx).unwrap_err();
        assert!(err.to_string().contains("frames[0].data"), "{err}");

        // Sender must be a 20-byte address.
        let mut tx = create_test_tx();
        tx.sender = "0x1234".to_string();
        let err = Eip8141Encoder::validate_wire_format(&tx).unwrap_err();
        assert!(err.to_string().contains("sender"), "{err}");

        // Garbled value strings must not silently encode as zero.
        let mut tx = create_test_tx();
        tx.frames[0].value = "one ether".to_string();
        let err = Eip8141Encoder::validate_wire_format(&tx).unwrap_err();
        assert!(err.to_string().contains("frames[0].value"), "{err}");

        // A non-empty signature msg must be an explicit 32-byte digest.
        let mut tx = create_test_tx();
        tx.signatures[0].msg = "0x1234".to_string();
        let err = Eip8141Encoder::validate_wire_format(&tx).unwrap_err();
        assert!(err.to_string().contains("signatures[0].msg"), "{err}");
    }

    #[test]
    fn wire_format_accepts_placeholders() {
        // Empty target (resolves to sender), empty signature (sponsor
        // placeholder), and empty msg (canonical sig hash) are all valid.
        let mut tx = create_test_tx();
        tx.frames[0].target = None;
        tx.frames[0].value = "".to_string();
        tx.signatures[0].signature = "".to_string();
        tx.signatures[0].msg = "".to_string();
        assert!(Eip8141Encoder::validate_wire_format(&tx).is_ok());
    }

    #[test]
    fn encode_transaction_includes_prefix() {
        let tx = create_test_tx();
        let encoded = Eip8141Encoder::encode_transaction(&tx);

        // EIP-8141 defines FRAME_TX_TYPE as 0x06
        assert_eq!(encoded[0], 0x06);

        // Ensure it's successfully encoded into multiple bytes
        assert!(encoded.len() > 10);
    }

    #[test]
    fn encode_transaction_sender_follows_keyed_nonce() {
        let tx = create_test_tx();
        let encoded = Eip8141Encoder::encode_transaction(&tx);
        let payload = &encoded[1..];

        let (header, mut offset) = decode_header(payload);
        assert!(header.list);

        // EIP-8250 layout: chain_id, nonce_keys (list), nonce_seq, sender, ...
        let (_chain_id, chain_id_len) = decode_item(&payload[offset..]);
        offset += chain_id_len;
        let (nonce_keys_header, nonce_keys_len) = decode_item(&payload[offset..]);
        assert!(nonce_keys_header.list, "nonce_keys must encode as an RLP list");
        offset += nonce_keys_len;
        let (_nonce_seq, nonce_seq_len) = decode_item(&payload[offset..]);
        offset += nonce_seq_len;
        let (sender_header, _sender_len) = decode_header(&payload[offset..]);

        assert!(
            !sender_header.list,
            "sender field starts at offset {offset} with byte 0x{:02x}",
            payload[offset]
        );
        assert_eq!(sender_header.payload_length, 20);
    }

    fn decode_item(input: &[u8]) -> (alloy::rlp::Header, usize) {
        let (header, header_len) = decode_header(input);
        let item_len = header_len + header.payload_length;
        (header, item_len)
    }

    fn decode_header(input: &[u8]) -> (alloy::rlp::Header, usize) {
        let first = input[0];
        if first <= 0x7f {
            return (
                alloy::rlp::Header {
                    list: false,
                    payload_length: 1,
                },
                0,
            );
        }
        if first <= 0xb7 {
            return (
                alloy::rlp::Header {
                    list: false,
                    payload_length: (first - 0x80) as usize,
                },
                1,
            );
        }
        if first <= 0xbf {
            let len_of_len = (first - 0xb7) as usize;
            let payload_length =
                usize::from_be_bytes(left_pad_usize(&input[1..1 + len_of_len]));
            return (
                alloy::rlp::Header {
                    list: false,
                    payload_length,
                },
                1 + len_of_len,
            );
        }
        if first <= 0xf7 {
            return (
                alloy::rlp::Header {
                    list: true,
                    payload_length: (first - 0xc0) as usize,
                },
                1,
            );
        }

        let len_of_len = (first - 0xf7) as usize;
        let payload_length = usize::from_be_bytes(left_pad_usize(&input[1..1 + len_of_len]));
        (
            alloy::rlp::Header {
                list: true,
                payload_length,
            },
            1 + len_of_len,
        )
    }

    fn left_pad_usize(input: &[u8]) -> [u8; std::mem::size_of::<usize>()] {
        let mut output = [0; std::mem::size_of::<usize>()];
        let start = output.len() - input.len();
        output[start..].copy_from_slice(input);
        output
    }
}
