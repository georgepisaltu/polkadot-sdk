// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

use async_trait::async_trait;
use polkadot_primitives::{
	async_backing,
	runtime_api::ParachainHost,
	slashing,
	vstaging::{
		self, async_backing::Constraints, CandidateEvent,
		CommittedCandidateReceiptV2 as CommittedCandidateReceipt, CoreState, ScrapedOnChainVotes,
	},
	ApprovalVotingParams, Block, BlockNumber, CandidateCommitments, CandidateHash, CoreIndex,
	DisputeState, ExecutorParams, GroupRotationInfo, Hash, Header, Id, InboundDownwardMessage,
	InboundHrmpMessage, NodeFeatures, OccupiedCoreAssumption, PersistedValidationData,
	PvfCheckStatement, SessionIndex, SessionInfo, ValidationCode, ValidationCodeHash, ValidatorId,
	ValidatorIndex, ValidatorSignature,
};
use sc_client_api::{AuxStore, HeaderBackend};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sp_api::{ApiError, ApiExt, ProvideRuntimeApi};
use sp_authority_discovery::AuthorityDiscoveryApi;
use sp_blockchain::{BlockStatus, Info};
use sp_consensus_babe::{BabeApi, Epoch};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use std::{
	collections::{BTreeMap, VecDeque},
	sync::Arc,
};

/// Offers header utilities.
///
/// This is a async wrapper trait for ['HeaderBackend'] to be used with the
/// `ChainApiSubsystem`.
// This trait was introduced to suit the needs of collators. Depending on their operating mode, they
// might not have a client of the relay chain that can supply a synchronous HeaderBackend
// implementation.
#[async_trait]
pub trait ChainApiBackend: Send + Sync {
	/// Get block header. Returns `None` if block is not found.
	async fn header(&self, hash: Hash) -> sp_blockchain::Result<Option<Header>>;
	/// Get blockchain info.
	async fn info(&self) -> sp_blockchain::Result<Info<Block>>;
	/// Get block number by hash. Returns `None` if the header is not in the chain.
	async fn number(
		&self,
		hash: Hash,
	) -> sp_blockchain::Result<Option<<Header as HeaderT>::Number>>;
	/// Get block hash by number. Returns `None` if the header is not in the chain.
	async fn hash(&self, number: NumberFor<Block>) -> sp_blockchain::Result<Option<Hash>>;
}

#[async_trait]
impl<T> ChainApiBackend for T
where
	T: HeaderBackend<Block>,
{
	/// Get block header. Returns `None` if block is not found.
	async fn header(&self, hash: Hash) -> sp_blockchain::Result<Option<Header>> {
		HeaderBackend::header(self, hash)
	}

	/// Get blockchain info.
	async fn info(&self) -> sp_blockchain::Result<Info<Block>> {
		Ok(HeaderBackend::info(self))
	}

	/// Get block number by hash. Returns `None` if the header is not in the chain.
	async fn number(
		&self,
		hash: Hash,
	) -> sp_blockchain::Result<Option<<Header as HeaderT>::Number>> {
		HeaderBackend::number(self, hash)
	}

	/// Get block hash by number. Returns `None` if the header is not in the chain.
	async fn hash(&self, number: NumberFor<Block>) -> sp_blockchain::Result<Option<Hash>> {
		HeaderBackend::hash(self, number)
	}
}

/// Exposes all runtime calls that are used by the runtime API subsystem.
#[async_trait]
pub trait RuntimeApiSubsystemClient {
	/// Parachain host API version
	async fn api_version_parachain_host(&self, at: Hash) -> Result<Option<u32>, ApiError>;

	// === ParachainHost API ===

	/// Get the current validators.
	async fn validators(&self, at: Hash) -> Result<Vec<ValidatorId>, ApiError>;

	/// Returns the validator groups and rotation info localized based on the hypothetical child
	///  of a block whose state  this is invoked on. Note that `now` in the `GroupRotationInfo`
	/// should be the successor of the number of the block.
	async fn validator_groups(
		&self,
		at: Hash,
	) -> Result<(Vec<Vec<ValidatorIndex>>, GroupRotationInfo<BlockNumber>), ApiError>;

	/// Yields information on all availability cores as relevant to the child block.
	/// Cores are either free or occupied. Free cores can have paras assigned to them.
	async fn availability_cores(
		&self,
		at: Hash,
	) -> Result<Vec<CoreState<Hash, BlockNumber>>, ApiError>;

	/// Yields the persisted validation data for the given `ParaId` along with an assumption that
	/// should be used if the para currently occupies a core.
	///
	/// Returns `None` if either the para is not registered or the assumption is `Freed`
	/// and the para already occupies a core.
	async fn persisted_validation_data(
		&self,
		at: Hash,
		para_id: Id,
		assumption: OccupiedCoreAssumption,
	) -> Result<Option<PersistedValidationData<Hash, BlockNumber>>, ApiError>;

	/// Returns the persisted validation data for the given `ParaId` along with the corresponding
	/// validation code hash. Instead of accepting assumption about the para, matches the validation
	/// data hash against an expected one and yields `None` if they're not equal.
	async fn assumed_validation_data(
		&self,
		at: Hash,
		para_id: Id,
		expected_persisted_validation_data_hash: Hash,
	) -> Result<Option<(PersistedValidationData<Hash, BlockNumber>, ValidationCodeHash)>, ApiError>;

	/// Checks if the given validation outputs pass the acceptance criteria.
	async fn check_validation_outputs(
		&self,
		at: Hash,
		para_id: Id,
		outputs: CandidateCommitments,
	) -> Result<bool, ApiError>;

	/// Returns the session index expected at a child of the block.
	///
	/// This can be used to instantiate a `SigningContext`.
	async fn session_index_for_child(&self, at: Hash) -> Result<SessionIndex, ApiError>;

	/// Fetch the validation code used by a para, making the given `OccupiedCoreAssumption`.
	///
	/// Returns `None` if either the para is not registered or the assumption is `Freed`
	/// and the para already occupies a core.
	async fn validation_code(
		&self,
		at: Hash,
		para_id: Id,
		assumption: OccupiedCoreAssumption,
	) -> Result<Option<ValidationCode>, ApiError>;

	/// Get the receipt of a candidate pending availability. This returns `Some` for any paras
	/// assigned to occupied cores in `availability_cores` and `None` otherwise.
	async fn candidate_pending_availability(
		&self,
		at: Hash,
		para_id: Id,
	) -> Result<Option<CommittedCandidateReceipt<Hash>>, ApiError>;

	/// Get a vector of events concerning candidates that occurred within a block.
	async fn candidate_events(&self, at: Hash) -> Result<Vec<CandidateEvent<Hash>>, ApiError>;

	/// Get all the pending inbound messages in the downward message queue for a para.
	async fn dmq_contents(
		&self,
		at: Hash,
		recipient: Id,
	) -> Result<Vec<InboundDownwardMessage<BlockNumber>>, ApiError>;

	/// Get the contents of all channels addressed to the given recipient. Channels that have no
	/// messages in them are also included.
	async fn inbound_hrmp_channels_contents(
		&self,
		at: Hash,
		recipient: Id,
	) -> Result<BTreeMap<Id, Vec<InboundHrmpMessage<BlockNumber>>>, ApiError>;

	/// Get the validation code from its hash.
	async fn validation_code_by_hash(
		&self,
		at: Hash,
		hash: ValidationCodeHash,
	) -> Result<Option<ValidationCode>, ApiError>;

	/// Scrape dispute relevant from on-chain, backing votes and resolved disputes.
	async fn on_chain_votes(&self, at: Hash)
		-> Result<Option<ScrapedOnChainVotes<Hash>>, ApiError>;

	/***** Added in v2 **** */

	/// Get the session info for the given session, if stored.
	///
	/// NOTE: This function is only available since parachain host version 2.
	async fn session_info(
		&self,
		at: Hash,
		index: SessionIndex,
	) -> Result<Option<SessionInfo>, ApiError>;

	/// Submits a PVF pre-checking statement into the transaction pool.
	///
	/// NOTE: This function is only available since parachain host version 2.
	async fn submit_pvf_check_statement(
		&self,
		at: Hash,
		stmt: PvfCheckStatement,
		signature: ValidatorSignature,
	) -> Result<(), ApiError>;

	/// Returns code hashes of PVFs that require pre-checking by validators in the active set.
	///
	/// NOTE: This function is only available since parachain host version 2.
	async fn pvfs_require_precheck(&self, at: Hash) -> Result<Vec<ValidationCodeHash>, ApiError>;

	/// Fetch the hash of the validation code used by a para, making the given
	/// `OccupiedCoreAssumption`.
	///
	/// NOTE: This function is only available since parachain host version 2.
	async fn validation_code_hash(
		&self,
		at: Hash,
		para_id: Id,
		assumption: OccupiedCoreAssumption,
	) -> Result<Option<ValidationCodeHash>, ApiError>;

	/***** Added in v3 **** */

	/// Returns all onchain disputes.
	async fn disputes(
		&self,
		at: Hash,
	) -> Result<Vec<(SessionIndex, CandidateHash, DisputeState<BlockNumber>)>, ApiError>;

	/// Returns a list of validators that lost a past session dispute and need to be slashed.
	async fn unapplied_slashes(
		&self,
		at: Hash,
	) -> Result<Vec<(SessionIndex, CandidateHash, slashing::PendingSlashes)>, ApiError>;

	/// Returns a merkle proof of a validator session key in a past session.
	async fn key_ownership_proof(
		&self,
		at: Hash,
		validator_id: ValidatorId,
	) -> Result<Option<slashing::OpaqueKeyOwnershipProof>, ApiError>;

	/// Submits an unsigned extrinsic to slash validators who lost a dispute about
	/// a candidate of a past session.
	async fn submit_report_dispute_lost(
		&self,
		at: Hash,
		dispute_proof: slashing::DisputeProof,
		key_ownership_proof: slashing::OpaqueKeyOwnershipProof,
	) -> Result<Option<()>, ApiError>;

	// === BABE API ===

	/// Returns information regarding the current epoch.
	async fn current_epoch(&self, at: Hash) -> Result<Epoch, ApiError>;

	// === AuthorityDiscovery API ===

	/// Retrieve authority identifiers of the current and next authority set.
	async fn authorities(
		&self,
		at: Hash,
	) -> std::result::Result<Vec<sp_authority_discovery::AuthorityId>, ApiError>;

	/// Get the execution environment parameter set by parent hash, if stored
	async fn session_executor_params(
		&self,
		at: Hash,
		session_index: SessionIndex,
	) -> Result<Option<ExecutorParams>, ApiError>;

	// === v6 ===
	/// Get the minimum number of backing votes.
	async fn minimum_backing_votes(
		&self,
		at: Hash,
		session_index: SessionIndex,
	) -> Result<u32, ApiError>;

	// === v7: Asynchronous backing API ===

	/// Returns candidate's acceptance limitations for asynchronous backing for a relay parent.
	async fn async_backing_params(
		&self,
		at: Hash,
	) -> Result<polkadot_primitives::AsyncBackingParams, ApiError>;

	/// Returns the state of parachain backing for a given para.
	/// This is a staging method! Do not use on production runtimes!
	async fn para_backing_state(
		&self,
		at: Hash,
		para_id: Id,
	) -> Result<Option<vstaging::async_backing::BackingState>, ApiError>;

	// === v8 ===

	/// Gets the disabled validators at a specific block height
	async fn disabled_validators(&self, at: Hash) -> Result<Vec<ValidatorIndex>, ApiError>;

	// === v9 ===
	/// Get the node features.
	async fn node_features(&self, at: Hash) -> Result<NodeFeatures, ApiError>;

	// == v10: Approval voting params ==
	/// Approval voting configuration parameters
	async fn approval_voting_params(
		&self,
		at: Hash,
		session_index: SessionIndex,
	) -> Result<ApprovalVotingParams, ApiError>;

	// == v11: Claim queue ==
	/// Fetch the `ClaimQueue` from scheduler pallet
	async fn claim_queue(&self, at: Hash) -> Result<BTreeMap<CoreIndex, VecDeque<Id>>, ApiError>;

	// == v11: Elastic scaling support ==
	/// Get the receipts of all candidates pending availability for a `ParaId`.
	async fn candidates_pending_availability(
		&self,
		at: Hash,
		para_id: Id,
	) -> Result<Vec<CommittedCandidateReceipt<Hash>>, ApiError>;

	// == v12 ==
	/// Get the constraints on the actions that can be taken by a new parachain
	/// block.
	async fn backing_constraints(
		&self,
		at: Hash,
		para_id: Id,
	) -> Result<Option<Constraints>, ApiError>;

	// === v12 ===
	/// Fetch the scheduling lookahead value
	async fn scheduling_lookahead(&self, at: Hash) -> Result<u32, ApiError>;

	// === v12 ===
	/// Fetch the maximum uncompressed code size.
	async fn validation_code_bomb_limit(&self, at: Hash) -> Result<u32, ApiError>;

	// == v14 ==
	/// Fetch the list of all parachain IDs registered in the relay chain.
	async fn para_ids(&self, at: Hash) -> Result<Vec<Id>, ApiError>;
}

/// Default implementation of [`RuntimeApiSubsystemClient`] using the client.
pub struct DefaultSubsystemClient<Client> {
	client: Arc<Client>,
	offchain_transaction_pool_factory: OffchainTransactionPoolFactory<Block>,
}

impl<Client> DefaultSubsystemClient<Client> {
	/// Create new instance.
	pub fn new(
		client: Arc<Client>,
		offchain_transaction_pool_factory: OffchainTransactionPoolFactory<Block>,
	) -> Self {
		Self { client, offchain_transaction_pool_factory }
	}
}

#[async_trait]
impl<Client> RuntimeApiSubsystemClient for DefaultSubsystemClient<Client>
where
	Client: ProvideRuntimeApi<Block> + Send + Sync,
	Client::Api: ParachainHost<Block> + BabeApi<Block> + AuthorityDiscoveryApi<Block>,
{
	async fn validators(&self, at: Hash) -> Result<Vec<ValidatorId>, ApiError> {
		self.client.runtime_api().validators(at)
	}

	async fn validator_groups(
		&self,
		at: Hash,
	) -> Result<(Vec<Vec<ValidatorIndex>>, GroupRotationInfo<BlockNumber>), ApiError> {
		self.client.runtime_api().validator_groups(at)
	}

	async fn availability_cores(
		&self,
		at: Hash,
	) -> Result<Vec<CoreState<Hash, BlockNumber>>, ApiError> {
		self.client.runtime_api().availability_cores(at)
	}

	async fn persisted_validation_data(
		&self,
		at: Hash,
		para_id: Id,
		assumption: OccupiedCoreAssumption,
	) -> Result<Option<PersistedValidationData<Hash, BlockNumber>>, ApiError> {
		self.client.runtime_api().persisted_validation_data(at, para_id, assumption)
	}

	async fn assumed_validation_data(
		&self,
		at: Hash,
		para_id: Id,
		expected_persisted_validation_data_hash: Hash,
	) -> Result<Option<(PersistedValidationData<Hash, BlockNumber>, ValidationCodeHash)>, ApiError>
	{
		self.client.runtime_api().assumed_validation_data(
			at,
			para_id,
			expected_persisted_validation_data_hash,
		)
	}

	async fn check_validation_outputs(
		&self,
		at: Hash,
		para_id: Id,
		outputs: CandidateCommitments,
	) -> Result<bool, ApiError> {
		self.client.runtime_api().check_validation_outputs(at, para_id, outputs)
	}

	async fn session_index_for_child(&self, at: Hash) -> Result<SessionIndex, ApiError> {
		self.client.runtime_api().session_index_for_child(at)
	}

	async fn validation_code(
		&self,
		at: Hash,
		para_id: Id,
		assumption: OccupiedCoreAssumption,
	) -> Result<Option<ValidationCode>, ApiError> {
		self.client.runtime_api().validation_code(at, para_id, assumption)
	}

	async fn candidate_pending_availability(
		&self,
		at: Hash,
		para_id: Id,
	) -> Result<Option<CommittedCandidateReceipt<Hash>>, ApiError> {
		self.client.runtime_api().candidate_pending_availability(at, para_id)
	}

	async fn candidates_pending_availability(
		&self,
		at: Hash,
		para_id: Id,
	) -> Result<Vec<CommittedCandidateReceipt<Hash>>, ApiError> {
		self.client.runtime_api().candidates_pending_availability(at, para_id)
	}

	async fn candidate_events(&self, at: Hash) -> Result<Vec<CandidateEvent<Hash>>, ApiError> {
		self.client.runtime_api().candidate_events(at)
	}

	async fn dmq_contents(
		&self,
		at: Hash,
		recipient: Id,
	) -> Result<Vec<InboundDownwardMessage<BlockNumber>>, ApiError> {
		self.client.runtime_api().dmq_contents(at, recipient)
	}

	async fn inbound_hrmp_channels_contents(
		&self,
		at: Hash,
		recipient: Id,
	) -> Result<BTreeMap<Id, Vec<InboundHrmpMessage<BlockNumber>>>, ApiError> {
		self.client.runtime_api().inbound_hrmp_channels_contents(at, recipient)
	}

	async fn validation_code_by_hash(
		&self,
		at: Hash,
		hash: ValidationCodeHash,
	) -> Result<Option<ValidationCode>, ApiError> {
		self.client.runtime_api().validation_code_by_hash(at, hash)
	}

	async fn on_chain_votes(
		&self,
		at: Hash,
	) -> Result<Option<ScrapedOnChainVotes<Hash>>, ApiError> {
		self.client.runtime_api().on_chain_votes(at)
	}

	async fn session_executor_params(
		&self,
		at: Hash,
		session_index: SessionIndex,
	) -> Result<Option<ExecutorParams>, ApiError> {
		self.client.runtime_api().session_executor_params(at, session_index)
	}

	async fn session_info(
		&self,
		at: Hash,
		index: SessionIndex,
	) -> Result<Option<SessionInfo>, ApiError> {
		self.client.runtime_api().session_info(at, index)
	}

	async fn submit_pvf_check_statement(
		&self,
		at: Hash,
		stmt: PvfCheckStatement,
		signature: ValidatorSignature,
	) -> Result<(), ApiError> {
		let mut runtime_api = self.client.runtime_api();

		runtime_api.register_extension(
			self.offchain_transaction_pool_factory.offchain_transaction_pool(at),
		);

		runtime_api.submit_pvf_check_statement(at, stmt, signature)
	}

	async fn pvfs_require_precheck(&self, at: Hash) -> Result<Vec<ValidationCodeHash>, ApiError> {
		self.client.runtime_api().pvfs_require_precheck(at)
	}

	async fn validation_code_hash(
		&self,
		at: Hash,
		para_id: Id,
		assumption: OccupiedCoreAssumption,
	) -> Result<Option<ValidationCodeHash>, ApiError> {
		self.client.runtime_api().validation_code_hash(at, para_id, assumption)
	}

	async fn current_epoch(&self, at: Hash) -> Result<Epoch, ApiError> {
		self.client.runtime_api().current_epoch(at)
	}

	async fn authorities(
		&self,
		at: Hash,
	) -> std::result::Result<Vec<sp_authority_discovery::AuthorityId>, ApiError> {
		self.client.runtime_api().authorities(at)
	}

	async fn api_version_parachain_host(&self, at: Hash) -> Result<Option<u32>, ApiError> {
		self.client.runtime_api().api_version::<dyn ParachainHost<Block>>(at)
	}

	async fn disputes(
		&self,
		at: Hash,
	) -> Result<Vec<(SessionIndex, CandidateHash, DisputeState<BlockNumber>)>, ApiError> {
		self.client.runtime_api().disputes(at)
	}

	async fn unapplied_slashes(
		&self,
		at: Hash,
	) -> Result<Vec<(SessionIndex, CandidateHash, slashing::PendingSlashes)>, ApiError> {
		self.client.runtime_api().unapplied_slashes(at)
	}

	async fn key_ownership_proof(
		&self,
		at: Hash,
		validator_id: ValidatorId,
	) -> Result<Option<slashing::OpaqueKeyOwnershipProof>, ApiError> {
		self.client.runtime_api().key_ownership_proof(at, validator_id)
	}

	async fn submit_report_dispute_lost(
		&self,
		at: Hash,
		dispute_proof: slashing::DisputeProof,
		key_ownership_proof: slashing::OpaqueKeyOwnershipProof,
	) -> Result<Option<()>, ApiError> {
		let mut runtime_api = self.client.runtime_api();

		runtime_api.register_extension(
			self.offchain_transaction_pool_factory.offchain_transaction_pool(at),
		);

		runtime_api.submit_report_dispute_lost(at, dispute_proof, key_ownership_proof)
	}

	async fn minimum_backing_votes(
		&self,
		at: Hash,
		_session_index: SessionIndex,
	) -> Result<u32, ApiError> {
		self.client.runtime_api().minimum_backing_votes(at)
	}

	async fn para_backing_state(
		&self,
		at: Hash,
		para_id: Id,
	) -> Result<Option<vstaging::async_backing::BackingState>, ApiError> {
		self.client.runtime_api().para_backing_state(at, para_id)
	}

	async fn async_backing_params(
		&self,
		at: Hash,
	) -> Result<async_backing::AsyncBackingParams, ApiError> {
		self.client.runtime_api().async_backing_params(at)
	}

	async fn node_features(&self, at: Hash) -> Result<NodeFeatures, ApiError> {
		self.client.runtime_api().node_features(at)
	}

	async fn disabled_validators(&self, at: Hash) -> Result<Vec<ValidatorIndex>, ApiError> {
		self.client.runtime_api().disabled_validators(at)
	}

	/// Approval voting configuration parameters
	async fn approval_voting_params(
		&self,
		at: Hash,
		_session_index: SessionIndex,
	) -> Result<ApprovalVotingParams, ApiError> {
		self.client.runtime_api().approval_voting_params(at)
	}

	async fn claim_queue(&self, at: Hash) -> Result<BTreeMap<CoreIndex, VecDeque<Id>>, ApiError> {
		self.client.runtime_api().claim_queue(at)
	}

	async fn backing_constraints(
		&self,
		at: Hash,
		para_id: Id,
	) -> Result<Option<Constraints>, ApiError> {
		self.client.runtime_api().backing_constraints(at, para_id)
	}

	async fn scheduling_lookahead(&self, at: Hash) -> Result<u32, ApiError> {
		self.client.runtime_api().scheduling_lookahead(at)
	}

	async fn validation_code_bomb_limit(&self, at: Hash) -> Result<u32, ApiError> {
		self.client.runtime_api().validation_code_bomb_limit(at)
	}

	async fn para_ids(&self, at: Hash) -> Result<Vec<Id>, ApiError> {
		self.client.runtime_api().para_ids(at)
	}
}

impl<Client, Block> HeaderBackend<Block> for DefaultSubsystemClient<Client>
where
	Client: HeaderBackend<Block>,
	Block: sp_runtime::traits::Block,
{
	fn header(
		&self,
		hash: Block::Hash,
	) -> sc_client_api::blockchain::Result<Option<Block::Header>> {
		self.client.header(hash)
	}

	fn info(&self) -> Info<Block> {
		self.client.info()
	}

	fn status(&self, hash: Block::Hash) -> sc_client_api::blockchain::Result<BlockStatus> {
		self.client.status(hash)
	}

	fn number(
		&self,
		hash: Block::Hash,
	) -> sc_client_api::blockchain::Result<Option<<<Block as BlockT>::Header as HeaderT>::Number>>
	{
		self.client.number(hash)
	}

	fn hash(
		&self,
		number: NumberFor<Block>,
	) -> sc_client_api::blockchain::Result<Option<Block::Hash>> {
		self.client.hash(number)
	}
}

impl<Client> AuxStore for DefaultSubsystemClient<Client>
where
	Client: AuxStore,
{
	fn insert_aux<
		'a,
		'b: 'a,
		'c: 'a,
		I: IntoIterator<Item = &'a (&'c [u8], &'c [u8])>,
		D: IntoIterator<Item = &'a &'b [u8]>,
	>(
		&self,
		insert: I,
		delete: D,
	) -> sp_blockchain::Result<()> {
		self.client.insert_aux(insert, delete)
	}

	fn get_aux(&self, key: &[u8]) -> sp_blockchain::Result<Option<Vec<u8>>> {
		self.client.get_aux(key)
	}
}
