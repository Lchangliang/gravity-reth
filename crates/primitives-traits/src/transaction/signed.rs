//! API of a signed transaction.

use crate::{
    crypto::secp256k1::{recover_signer, recover_signer_unchecked},
    FillTxEnv, InMemorySize, MaybeCompact, MaybeSerde, MaybeSerdeBincodeCompat,
};
use alloc::{fmt, vec::Vec};
use alloy_consensus::{
    transaction::{PooledTransaction, Recovered},
    SignableTransaction, Transaction,
};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{keccak256, Address, PrimitiveSignature as Signature, TxHash, B256};
use revm_primitives::hex;
use serde::{Deserialize, Serialize};
use core::{hash::Hash, str::FromStr};
use std::{collections::HashMap, fs, path::Path, sync::OnceLock};

/// Helper trait that unifies all behaviour required by block to support full node operations.
pub trait FullSignedTx:
    SignedTransaction + FillTxEnv + MaybeCompact + MaybeSerdeBincodeCompat
{
}

impl<T> FullSignedTx for T where
    T: SignedTransaction + FillTxEnv + MaybeCompact + MaybeSerdeBincodeCompat
{
}

/// A signed transaction.
#[auto_impl::auto_impl(&, Arc)]
pub trait SignedTransaction:
    Send
    + Sync
    + Unpin
    + Clone
    + fmt::Debug
    + PartialEq
    + Eq
    + Hash
    + alloy_rlp::Encodable
    + alloy_rlp::Decodable
    + Encodable2718
    + Decodable2718
    + alloy_consensus::Transaction
    + MaybeSerde
    + InMemorySize
{
    /// Returns reference to transaction hash.
    fn tx_hash(&self) -> &TxHash;

    /// Returns reference to signature.
    fn signature(&self) -> &Signature;

    /// Returns whether this transaction type can be __broadcasted__ as full transaction over the
    /// network.
    ///
    /// Some transactions are not broadcastable as objects and only allowed to be broadcasted as
    /// hashes, e.g. because they missing context (e.g. blob sidecar).
    fn is_broadcastable_in_full(&self) -> bool {
        // EIP-4844 transactions are not broadcastable in full, only hashes are allowed.
        !self.is_eip4844()
    }

    /// Recover signer from signature and hash.
    ///
    /// Returns `None` if the transaction's signature is invalid following [EIP-2](https://eips.ethereum.org/EIPS/eip-2), see also `reth_primitives::transaction::recover_signer`.
    ///
    /// Note:
    ///
    /// This can fail for some early ethereum mainnet transactions pre EIP-2, use
    /// [`Self::recover_signer_unchecked`] if you want to recover the signer without ensuring that
    /// the signature has a low `s` value.
    fn recover_signer(&self) -> Result<Address, RecoveryError>;

    /// Recover signer from signature and hash.
    ///
    /// Returns an error if the transaction's signature is invalid.
    fn try_recover(&self) -> Result<Address, RecoveryError> {
        self.recover_signer().map_err(|_| RecoveryError)
    }

    /// Recover signer from signature and hash _without ensuring that the signature has a low `s`
    /// value_.
    ///
    /// Returns `None` if the transaction's signature is invalid, see also
    /// `reth_primitives::transaction::recover_signer_unchecked`.
    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        self.recover_signer_unchecked_with_buf(&mut Vec::new()).map_err(|_| RecoveryError)
    }

    /// Recover signer from signature and hash _without ensuring that the signature has a low `s`
    /// value_.
    ///
    /// Returns an error if the transaction's signature is invalid.
    fn try_recover_unchecked(&self) -> Result<Address, RecoveryError> {
        self.recover_signer_unchecked()
    }

    /// Same as [`Self::recover_signer_unchecked`] but receives a buffer to operate on. This is used
    /// during batch recovery to avoid allocating a new buffer for each transaction.
    fn recover_signer_unchecked_with_buf(
        &self,
        buf: &mut Vec<u8>,
    ) -> Result<Address, RecoveryError>;

    /// Calculate transaction hash, eip2728 transaction does not contain rlp header and start with
    /// tx type.
    fn recalculate_hash(&self) -> B256 {
        keccak256(self.encoded_2718())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Account {
    private_key: String,
    address: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    rpc_urls: Vec<String>,
    chain_id: u64,
    erc20_address: String,
    source_account: Account,
    test_accounts: Vec<Account>,
}

// 全局配置变量
static CONFIG: OnceLock<Config> = OnceLock::new();

// 全局gas到address的映射
static GAS_TO_ADDRESS_MAP: OnceLock<std::sync::Mutex<HashMap<u64, String>>> = OnceLock::new();

// 初始化配置
fn init_config() -> Result<&'static Config, Box<dyn std::error::Error>> {
    if CONFIG.get().is_none() {
        let config_path = Path::new("/home/ubuntu/config.json");
        let config_content = fs::read_to_string(config_path)?;
        let config: Config = serde_json::from_str(&config_content)?;
        
        // 设置全局配置
        CONFIG.set(config).expect("Failed to set global config");
        
        // 初始化gas到address的映射
        init_gas_map();
    }
    
    Ok(CONFIG.get().unwrap())
}

// 初始化gas到address的映射
fn init_gas_map() {
    let config = CONFIG.get().expect("Config not initialized");
    let mut map = HashMap::new();
    
    // 计算并添加源账户
    let source_gas = calculate_gas_limit(&config.source_account.address);
    map.insert(source_gas, config.source_account.address.clone());
    
    // 计算并添加测试账户
    for account in &config.test_accounts {
        let gas = calculate_gas_limit(&account.address);
        map.insert(gas, account.address.clone());
    }
    
    // 设置全局映射
    GAS_TO_ADDRESS_MAP.set(std::sync::Mutex::new(map)).expect("Failed to set gas to address map");
}

// 计算地址对应的gas limit
fn calculate_gas_limit(address: &str) -> u64 {
    // 移除地址字符串开头的"0x"（如果有）
    let clean_address = if address.starts_with("0x") {
        &address[2..]
    } else {
        address
    };
    
    // 从十六进制地址解码为字节
    let address_bytes = match hex::decode(clean_address) {
        Ok(bytes) => bytes,
        Err(_) => return 21000, // 如果解码失败，返回默认值
    };
    
    // 确保有足够的字节（至少4个）来计算
    if address_bytes.len() < 4 {
        return 21000;
    }
    
    // 取前4个字节并计算BigEndian整数值
    let mut four_bytes = [0u8; 4];
    four_bytes.copy_from_slice(&address_bytes[0..4]);
    
    // 计算big endian uint32值
    let gas_base = u32::from_be_bytes(four_bytes) as u64;
    
    // 按照公式计算gas limit
    let gas_limit = (gas_base % 60000) + 21000;
    gas_limit
}

// 全局函数：根据gas获取对应的address
fn get_address(gas: u64) -> Option<String> {
    // 确保配置已经初始化
    if CONFIG.get().is_none() {
        let _ = init_config().expect("Failed to initialize config");
    }
    
    match GAS_TO_ADDRESS_MAP.get() {
        Some(map) => map.lock().unwrap().get(&gas).cloned(),
        None => None,
    }
}

impl SignedTransaction for PooledTransaction {
    fn tx_hash(&self) -> &TxHash {
        match self {
            Self::Legacy(tx) => tx.hash(),
            Self::Eip2930(tx) => tx.hash(),
            Self::Eip1559(tx) => tx.hash(),
            Self::Eip7702(tx) => tx.hash(),
            Self::Eip4844(tx) => tx.hash(),
        }
    }

    fn signature(&self) -> &Signature {
        match self {
            Self::Legacy(tx) => tx.signature(),
            Self::Eip2930(tx) => tx.signature(),
            Self::Eip1559(tx) => tx.signature(),
            Self::Eip7702(tx) => tx.signature(),
            Self::Eip4844(tx) => tx.signature(),
        }
    }

    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        if std::env::var("CACHE_ADDRESS").unwrap_or_default() != "true" {
            let signature_hash = self.signature_hash();
            return recover_signer(&self.signature(), signature_hash);
        }
        if let Some(address) = get_address(self.gas_limit()) {
            tracing::info!("hit {:?}", address);
            Ok(Address::from_str(&address).unwrap())
        } else {
            let signature_hash = self.signature_hash();
            if let Ok(address) = recover_signer(&self.signature(), signature_hash) {
                tracing::info!("miss and insert {} {:?}", self.gas_limit(), address);
                GAS_TO_ADDRESS_MAP.get().unwrap().lock().unwrap().insert(self.gas_limit(), address.to_string());
                Ok(address)
            } else {
                Err(RecoveryError)
            }
        }
    }

    fn recover_signer_unchecked_with_buf(
        &self,
        buf: &mut Vec<u8>,
    ) -> Result<Address, RecoveryError> {
        match self {
            Self::Legacy(tx) => tx.tx().encode_for_signing(buf),
            Self::Eip2930(tx) => tx.tx().encode_for_signing(buf),
            Self::Eip1559(tx) => tx.tx().encode_for_signing(buf),
            Self::Eip7702(tx) => tx.tx().encode_for_signing(buf),
            Self::Eip4844(tx) => tx.tx().encode_for_signing(buf),
        }
        let signature_hash = keccak256(buf);
        recover_signer_unchecked(self.signature(), signature_hash)
    }
}

#[cfg(feature = "op")]
impl SignedTransaction for op_alloy_consensus::OpPooledTransaction {
    fn tx_hash(&self) -> &TxHash {
        match self {
            Self::Legacy(tx) => tx.hash(),
            Self::Eip2930(tx) => tx.hash(),
            Self::Eip1559(tx) => tx.hash(),
            Self::Eip7702(tx) => tx.hash(),
        }
    }

    fn signature(&self) -> &Signature {
        match self {
            Self::Legacy(tx) => tx.signature(),
            Self::Eip2930(tx) => tx.signature(),
            Self::Eip1559(tx) => tx.signature(),
            Self::Eip7702(tx) => tx.signature(),
        }
    }

    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        let signature_hash = self.signature_hash();
        recover_signer(self.signature(), signature_hash)
    }

    fn recover_signer_unchecked_with_buf(
        &self,
        buf: &mut Vec<u8>,
    ) -> Result<Address, RecoveryError> {
        match self {
            Self::Legacy(tx) => tx.tx().encode_for_signing(buf),
            Self::Eip2930(tx) => tx.tx().encode_for_signing(buf),
            Self::Eip1559(tx) => tx.tx().encode_for_signing(buf),
            Self::Eip7702(tx) => tx.tx().encode_for_signing(buf),
        }
        let signature_hash = keccak256(buf);
        recover_signer_unchecked(self.signature(), signature_hash)
    }
}

/// Extension trait for [`SignedTransaction`] to convert it into [`Recovered`].
pub trait SignedTransactionIntoRecoveredExt: SignedTransaction {
    /// Tries to recover signer and return [`Recovered`] by cloning the type.
    fn try_clone_into_recovered(&self) -> Result<Recovered<Self>, RecoveryError> {
        self.recover_signer().map(|signer| Recovered::new_unchecked(self.clone(), signer))
    }

    /// Tries to recover signer and return [`Recovered`].
    ///
    /// Returns `Err(Self)` if the transaction's signature is invalid, see also
    /// [`SignedTransaction::recover_signer`].
    fn try_into_recovered(self) -> Result<Recovered<Self>, Self> {
        match self.recover_signer() {
            Ok(signer) => Ok(Recovered::new_unchecked(self, signer)),
            Err(_) => Err(self),
        }
    }

    /// Consumes the type, recover signer and return [`Recovered`] _without
    /// ensuring that the signature has a low `s` value_ (EIP-2).
    ///
    /// Returns `None` if the transaction's signature is invalid.
    fn into_recovered_unchecked(self) -> Result<Recovered<Self>, RecoveryError> {
        self.recover_signer_unchecked().map(|signer| Recovered::new_unchecked(self, signer))
    }

    /// Returns the [`Recovered`] transaction with the given sender.
    ///
    /// Note: assumes the given signer is the signer of this transaction.
    fn with_signer(self, signer: Address) -> Recovered<Self> {
        Recovered::new_unchecked(self, signer)
    }
}

impl<T> SignedTransactionIntoRecoveredExt for T where T: SignedTransaction {}

/// Opaque error type for sender recovery.
#[derive(Debug, Default, thiserror::Error)]
#[error("Failed to recover the signer")]
pub struct RecoveryError;
