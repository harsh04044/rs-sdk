//! RMCP integration scaffolding.
//!
//! This module will host adapters that bridge the existing Nostr transport
//! implementation with rmcp services.

pub mod convert;
pub mod worker;

pub use convert::{
	internal_to_rmcp_client_rx, internal_to_rmcp_server_rx, rmcp_client_tx_to_internal,
	rmcp_server_tx_to_internal,
};
pub use worker::{NostrClientWorker, NostrServerWorker};
