use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrameMode {
    Verify,
    Sender,
    Default,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub mode: FrameMode,
    pub flags: u8,
    pub target: String,
    pub gas_limit: u64,
    pub value: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameTransaction {
    pub chain_id: u64,
    pub nonce: Option<u64>,
    pub sender: String,
    pub max_priority_fee_per_gas: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub frames: Vec<Frame>,
}
