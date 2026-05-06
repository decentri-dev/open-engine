use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageQueueError {
    #[error("Redis error: {message}")]
    RedisError { message: String },

    #[error("JSON Serialization error: {message}")]
    JsonError { message: String },

    #[error("Runtime error: {message}")]
    Runtime { message: String },

    #[error("Worker panic: {message}")]
    WorkerPanic { message: String },
}

impl From<redis::RedisError> for MessageQueueError {
    fn from(error: redis::RedisError) -> Self {
        MessageQueueError::RedisError {
            message: error.to_string(),
        }
    }
}

impl From<serde_json::Error> for MessageQueueError {
    fn from(error: serde_json::Error) -> Self {
        MessageQueueError::JsonError {
            message: error.to_string(),
        }
    }
}
