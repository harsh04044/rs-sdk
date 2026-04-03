//! Conversion boundary between internal JSON-RPC messages and rmcp message types.
//!
//! These helpers intentionally convert via serde JSON to preserve wire-level
//! compatibility and avoid fragile hand-mapping between evolving type systems.

use crate::core::types::JsonRpcMessage;

/// Convert internal JSON-RPC message into rmcp server RX message.
///
/// Role mapping:
/// - RoleServer RX receives client-originated messages.
pub fn internal_to_rmcp_server_rx(
    msg: &JsonRpcMessage,
) -> Option<rmcp::service::RxJsonRpcMessage<rmcp::RoleServer>> {
    let value = serde_json::to_value(msg).ok()?;
    serde_json::from_value(value).ok()
}

/// Convert internal JSON-RPC message into rmcp client RX message.
///
/// Role mapping:
/// - RoleClient RX receives server-originated messages.
pub fn internal_to_rmcp_client_rx(
    msg: &JsonRpcMessage,
) -> Option<rmcp::service::RxJsonRpcMessage<rmcp::RoleClient>> {
    let value = serde_json::to_value(msg).ok()?;
    serde_json::from_value(value).ok()
}

/// Convert rmcp server TX message back into internal JSON-RPC.
pub fn rmcp_server_tx_to_internal(
    msg: rmcp::service::TxJsonRpcMessage<rmcp::RoleServer>,
) -> Option<JsonRpcMessage> {
    let value = serde_json::to_value(msg).ok()?;
    serde_json::from_value(value).ok()
}

/// Convert rmcp client TX message back into internal JSON-RPC.
pub fn rmcp_client_tx_to_internal(
    msg: rmcp::service::TxJsonRpcMessage<rmcp::RoleClient>,
) -> Option<JsonRpcMessage> {
    let value = serde_json::to_value(msg).ok()?;
    serde_json::from_value(value).ok()
}
