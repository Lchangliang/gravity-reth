//! Contains RPC handler implementations specific to transactions

use crate::{get_rpc_metrics, EthApi};
use alloy_primitives::{Bytes, B256};
use reth_provider::{BlockReader, BlockReaderIdExt, ProviderTx, TransactionsProvider};
use reth_rpc_eth_api::{
    helpers::{EthSigner, EthTransactions, LoadTransaction, SpawnBlocking},
    FromEthApiError, FullEthApiTypes, RpcNodeCore, RpcNodeCoreExt,
};
use reth_rpc_eth_types::utils::recover_raw_transaction;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};

impl<Provider, Pool, Network, EvmConfig> EthTransactions
    for EthApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadTransaction<Provider: BlockReaderIdExt>,
    Provider: BlockReader<Transaction = ProviderTx<Self::Provider>>,
{
    #[inline]
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner<ProviderTx<Self::Provider>>>>> {
        self.inner.signers()
    }

    /// Decodes and recovers the transaction and submits it to the pool.
    ///
    /// Returns the hash of the transaction.
    async fn send_raw_transaction(&self, tx: Bytes) -> Result<B256, Self::Error> {
        get_rpc_metrics().txn_recv_counter.increment(1);
        let recovered = recover_raw_transaction(&tx)?;

        // broadcast raw transaction to subscribers if there is any.
        self.broadcast_raw_transaction(tx);

        let pool_transaction = <Self::Pool as TransactionPool>::Transaction::from_pooled(recovered);

        // submit the transaction to the pool with a `Local` origin
        let hash = self
            .pool()
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .map_err(Self::Error::from_eth_err)?;

        Ok(hash)
    }
}

impl<Provider, Pool, Network, EvmConfig> LoadTransaction
    for EthApi<Provider, Pool, Network, EvmConfig>
where
    Self: SpawnBlocking
        + FullEthApiTypes
        + RpcNodeCoreExt<Provider: TransactionsProvider, Pool: TransactionPool>,
    Provider: BlockReader,
{
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use alloy_eips::eip1559::ETHEREUM_BLOCK_GAS_LIMIT_30M;
    use alloy_primitives::{hex_literal::hex, Bytes};
    use reth_chainspec::ChainSpecProvider;
    use reth_evm_ethereum::EthEvmConfig;
    use reth_network_api::noop::NoopNetwork;
    use reth_provider::test_utils::NoopProvider;
    use reth_rpc_eth_api::helpers::EthTransactions;
    use reth_rpc_eth_types::{
        EthStateCache, FeeHistoryCache, FeeHistoryCacheConfig, GasPriceOracle,
    };
    use reth_rpc_server_types::constants::{
        DEFAULT_ETH_PROOF_WINDOW, DEFAULT_MAX_SIMULATE_BLOCKS, DEFAULT_PROOF_PERMITS,
    };
    use reth_tasks::pool::BlockingTaskPool;
    use reth_transaction_pool::{test_utils::testing_pool, TransactionPool};

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn send_raw_transaction() {
        for _ in 0..1000 {
            let noop_provider = NoopProvider::default();
            let noop_network_provider = NoopNetwork::default();

            let pool = testing_pool();

            let evm_config = EthEvmConfig::new(noop_provider.chain_spec());
            let cache = EthStateCache::spawn(noop_provider.clone(), Default::default());
            let fee_history_cache = FeeHistoryCache::new(FeeHistoryCacheConfig::default());
            let eth_api = EthApi::new(
                noop_provider.clone(),
                pool.clone(),
                noop_network_provider,
                cache.clone(),
                GasPriceOracle::new(noop_provider, Default::default(), cache.clone()),
                ETHEREUM_BLOCK_GAS_LIMIT_30M,
                DEFAULT_MAX_SIMULATE_BLOCKS,
                DEFAULT_ETH_PROOF_WINDOW,
                BlockingTaskPool::build().expect("failed to build tracing pool"),
                fee_history_cache,
                evm_config,
                DEFAULT_PROOF_PERMITS,
            );

        // https://etherscan.io/tx/0xa694b71e6c128a2ed8e2e0f6770bddbe52e3bb8f10e8472f9a79ab81497a8b5d
        let tx_1 = Bytes::from(hex!("02f871018303579880850555633d1b82520894eee27662c2b8eba3cd936a23f039f3189633e4c887ad591c62bdaeb180c080a07ea72c68abfb8fca1bd964f0f99132ed9280261bdca3e549546c0205e800f7d0a05b4ef3039e9c9b9babc179a1878fb825b5aaf5aed2fa8744854150157b08d6f3"));
        let time_start = Instant::now();
        let tx_1_result = eth_api.send_raw_transaction(tx_1).await.unwrap();
        println!("send_raw_transaction time: {:?}", time_start.elapsed());
        assert_eq!(
            pool.len(),
            1,
            "expect 1 transactions in the pool, but pool size is {}",
            pool.len()
        );

            assert!(pool.get(&tx_1_result).is_some(), "tx1 not found in the pool");
            assert!(pool.get(&tx_2_result).is_some(), "tx2 not found in the pool");
        }
    }
}
