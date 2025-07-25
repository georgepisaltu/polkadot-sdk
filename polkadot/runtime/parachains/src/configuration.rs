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

//! Configuration manager for the Polkadot runtime parachains logic.
//!
//! Configuration can change only at session boundaries and is buffered until then.

use crate::shared;
use alloc::vec::Vec;
use codec::{Decode, Encode};
use frame_support::{pallet_prelude::*, DefaultNoBound};
use frame_system::pallet_prelude::*;
use polkadot_parachain_primitives::primitives::{
	MAX_HORIZONTAL_MESSAGE_NUM, MAX_UPWARD_MESSAGE_NUM,
};
use polkadot_primitives::{
	ApprovalVotingParams, AsyncBackingParams, Balance, ExecutorParamError, ExecutorParams,
	NodeFeatures, SessionIndex, LEGACY_MIN_BACKING_VOTES, MAX_CODE_SIZE, MAX_HEAD_DATA_SIZE,
	ON_DEMAND_MAX_QUEUE_MAX_SIZE,
};
use sp_runtime::{traits::Zero, Perbill, Percent};

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod migration;

pub use pallet::*;
use polkadot_primitives::SchedulerParams;

const LOG_TARGET: &str = "runtime::configuration";

// This value is derived from network layer limits. See `sc_network::MAX_RESPONSE_SIZE` and
// `polkadot_node_network_protocol::POV_RESPONSE_SIZE`.
const POV_SIZE_HARD_LIMIT: u32 = 16 * 1024 * 1024;

// The maximum compression ratio that we use to compute the maximum uncompressed code size.
pub(crate) const MAX_VALIDATION_CODE_COMPRESSION_RATIO: u32 = 10;

/// All configuration of the runtime with respect to paras.
#[derive(
	Clone,
	Encode,
	Decode,
	PartialEq,
	sp_core::RuntimeDebug,
	scale_info::TypeInfo,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct HostConfiguration<BlockNumber> {
	// NOTE: This structure is used by parachains via merkle proofs. Therefore, this struct
	// requires special treatment.
	//
	// A parachain requested this struct can only depend on the subset of this struct.
	// Specifically, only a first few fields can be depended upon. These fields cannot be changed
	// without corresponding migration of the parachains.
	/**
	 * The parameters that are required for the parachains.
	 */

	/// The maximum validation code size, in bytes.
	pub max_code_size: u32,
	/// The maximum head-data size, in bytes.
	pub max_head_data_size: u32,
	/// Total number of individual messages allowed in the parachain -> relay-chain message queue.
	pub max_upward_queue_count: u32,
	/// Total size of messages allowed in the parachain -> relay-chain message queue before which
	/// no further messages may be added to it. If it exceeds this then the queue may contain only
	/// a single message.
	pub max_upward_queue_size: u32,
	/// The maximum size of an upward message that can be sent by a candidate.
	///
	/// This parameter affects the size upper bound of the `CandidateCommitments`.
	pub max_upward_message_size: u32,
	/// The maximum number of messages that a candidate can contain.
	///
	/// This parameter affects the size upper bound of the `CandidateCommitments`.
	pub max_upward_message_num_per_candidate: u32,
	/// The maximum number of outbound HRMP messages can be sent by a candidate.
	///
	/// This parameter affects the upper bound of size of `CandidateCommitments`.
	pub hrmp_max_message_num_per_candidate: u32,
	/// The minimum period, in blocks, between which parachains can update their validation code.
	///
	/// This number is used to prevent parachains from spamming the relay chain with validation
	/// code upgrades. The only thing it controls is the number of blocks the
	/// `UpgradeRestrictionSignal` is set for the parachain in question.
	///
	/// If PVF pre-checking is enabled this should be greater than the maximum number of blocks
	/// PVF pre-checking can take. Intuitively, this number should be greater than the duration
	/// specified by [`pvf_voting_ttl`](Self::pvf_voting_ttl). Unlike,
	/// [`pvf_voting_ttl`](Self::pvf_voting_ttl), this parameter uses blocks as a unit.
	#[cfg_attr(feature = "std", serde(alias = "validation_upgrade_frequency"))]
	pub validation_upgrade_cooldown: BlockNumber,
	/// The delay, in blocks, after which an upgrade of the validation code is applied.
	///
	/// The upgrade for a parachain takes place when the first candidate which has relay-parent >=
	/// the relay-chain block where the upgrade is scheduled. This block is referred as to
	/// `expected_at`.
	///
	/// `expected_at` is determined when the upgrade is scheduled. This happens when the candidate
	/// that signals the upgrade is enacted. Right now, the relay-parent block number of the
	/// candidate scheduling the upgrade is used to determine the `expected_at`. This may change in
	/// the future with [#4601].
	///
	/// When PVF pre-checking is enabled, the upgrade is scheduled only after the PVF pre-check has
	/// been completed.
	///
	/// Note, there are situations in which `expected_at` in the past. For example, if
	/// [`paras_availability_period`](SchedulerParams::paras_availability_period) is less than the
	/// delay set by this field or if PVF pre-check took more time than the delay. In such cases,
	/// the upgrade is further at the earliest possible time determined by
	/// [`minimum_validation_upgrade_delay`](Self::minimum_validation_upgrade_delay).
	///
	/// The rationale for this delay has to do with relay-chain reversions. In case there is an
	/// invalid candidate produced with the new version of the code, then the relay-chain can
	/// revert [`validation_upgrade_delay`](Self::validation_upgrade_delay) many blocks back and
	/// still find the new code in the storage by hash.
	///
	/// [#4601]: https://github.com/paritytech/polkadot/issues/4601
	pub validation_upgrade_delay: BlockNumber,
	/// Asynchronous backing parameters.
	pub async_backing_params: AsyncBackingParams,

	/**
	 * The parameters that are not essential, but still may be of interest for parachains.
	 */

	/// The maximum POV block size, in bytes.
	pub max_pov_size: u32,
	/// The maximum size of a message that can be put in a downward message queue.
	///
	/// Since we require receiving at least one DMP message the obvious upper bound of the size is
	/// the PoV size. Of course, there is a lot of other different things that a parachain may
	/// decide to do with its PoV so this value in practice will be picked as a fraction of the PoV
	/// size.
	pub max_downward_message_size: u32,
	/// The maximum number of outbound HRMP channels a parachain is allowed to open.
	pub hrmp_max_parachain_outbound_channels: u32,
	/// The deposit that the sender should provide for opening an HRMP channel.
	pub hrmp_sender_deposit: Balance,
	/// The deposit that the recipient should provide for accepting opening an HRMP channel.
	pub hrmp_recipient_deposit: Balance,
	/// The maximum number of messages allowed in an HRMP channel at once.
	pub hrmp_channel_max_capacity: u32,
	/// The maximum total size of messages in bytes allowed in an HRMP channel at once.
	pub hrmp_channel_max_total_size: u32,
	/// The maximum number of inbound HRMP channels a parachain is allowed to accept.
	pub hrmp_max_parachain_inbound_channels: u32,
	/// The maximum size of a message that could ever be put into an HRMP channel.
	///
	/// This parameter affects the upper bound of size of `CandidateCommitments`.
	pub hrmp_channel_max_message_size: u32,
	/// The executor environment parameters
	pub executor_params: ExecutorParams,

	/**
	 * Parameters that will unlikely be needed by parachains.
	 */

	/// How long to keep code on-chain, in blocks. This should be sufficiently long that disputes
	/// have concluded.
	pub code_retention_period: BlockNumber,

	/// The maximum number of validators to use for parachain consensus, period.
	///
	/// `None` means no maximum.
	pub max_validators: Option<u32>,
	/// The amount of sessions to keep for disputes.
	pub dispute_period: SessionIndex,
	/// How long after dispute conclusion to accept statements.
	pub dispute_post_conclusion_acceptance_period: BlockNumber,
	/// The amount of consensus slots that must pass between submitting an assignment and
	/// submitting an approval vote before a validator is considered a no-show.
	///
	/// Must be at least 1.
	pub no_show_slots: u32,
	/// The number of delay tranches in total. Must be at least 1.
	pub n_delay_tranches: u32,
	/// The width of the zeroth delay tranche for approval assignments. This many delay tranches
	/// beyond 0 are all consolidated to form a wide 0 tranche.
	pub zeroth_delay_tranche_width: u32,
	/// The number of validators needed to approve a block.
	pub needed_approvals: u32,
	/// The number of samples to do of the `RelayVRFModulo` approval assignment criterion.
	pub relay_vrf_modulo_samples: u32,
	/// If an active PVF pre-checking vote observes this many number of sessions it gets
	/// automatically rejected.
	///
	/// 0 means PVF pre-checking will be rejected on the first observed session unless the voting
	/// gained supermajority before that the session change.
	pub pvf_voting_ttl: SessionIndex,
	/// The lower bound number of blocks an upgrade can be scheduled.
	///
	/// Typically, upgrade gets scheduled
	/// [`validation_upgrade_delay`](Self::validation_upgrade_delay) relay-chain blocks after
	/// the relay-parent of the parablock that signalled the validation code upgrade. However,
	/// in the case a pre-checking voting was concluded in a longer duration the upgrade will be
	/// scheduled to the next block.
	///
	/// That can disrupt parachain inclusion. Specifically, it will make the blocks that were
	/// already backed invalid.
	///
	/// To prevent that, we introduce the minimum number of blocks after which the upgrade can be
	/// scheduled. This number is controlled by this field.
	///
	/// This value should be greater than
	/// [`paras_availability_period`](SchedulerParams::paras_availability_period).
	pub minimum_validation_upgrade_delay: BlockNumber,
	/// The minimum number of valid backing statements required to consider a parachain candidate
	/// backable.
	pub minimum_backing_votes: u32,
	/// Node features enablement.
	pub node_features: NodeFeatures,
	/// Params used by approval-voting
	pub approval_voting_params: ApprovalVotingParams,
	/// Scheduler parameters
	pub scheduler_params: SchedulerParams<BlockNumber>,
}

impl<BlockNumber: Default + From<u32>> Default for HostConfiguration<BlockNumber> {
	fn default() -> Self {
		let ret = Self {
			async_backing_params: AsyncBackingParams {
				max_candidate_depth: 0,
				allowed_ancestry_len: 0,
			},
			no_show_slots: 1u32.into(),
			validation_upgrade_cooldown: Default::default(),
			validation_upgrade_delay: 2u32.into(),
			code_retention_period: Default::default(),
			max_code_size: MAX_CODE_SIZE,
			max_pov_size: Default::default(),
			max_head_data_size: Default::default(),
			max_validators: None,
			dispute_period: 6,
			dispute_post_conclusion_acceptance_period: 100.into(),
			n_delay_tranches: 1,
			zeroth_delay_tranche_width: Default::default(),
			needed_approvals: Default::default(),
			relay_vrf_modulo_samples: Default::default(),
			max_upward_queue_count: Default::default(),
			max_upward_queue_size: Default::default(),
			max_downward_message_size: Default::default(),
			max_upward_message_size: Default::default(),
			max_upward_message_num_per_candidate: Default::default(),
			hrmp_sender_deposit: Default::default(),
			hrmp_recipient_deposit: Default::default(),
			hrmp_channel_max_capacity: Default::default(),
			hrmp_channel_max_total_size: Default::default(),
			hrmp_max_parachain_inbound_channels: Default::default(),
			hrmp_channel_max_message_size: Default::default(),
			hrmp_max_parachain_outbound_channels: Default::default(),
			hrmp_max_message_num_per_candidate: Default::default(),
			pvf_voting_ttl: 2u32.into(),
			minimum_validation_upgrade_delay: 2.into(),
			executor_params: Default::default(),
			approval_voting_params: ApprovalVotingParams { max_approval_coalesce_count: 1 },
			minimum_backing_votes: LEGACY_MIN_BACKING_VOTES,
			node_features: NodeFeatures::EMPTY,
			scheduler_params: Default::default(),
		};

		#[cfg(feature = "runtime-benchmarks")]
		let ret = ret.with_benchmarking_default();
		ret
	}
}

#[cfg(feature = "runtime-benchmarks")]
impl<BlockNumber: Default + From<u32>> HostConfiguration<BlockNumber> {
	/// Mutate the values of self to be good estimates for benchmarking.
	///
	/// The values do not need to be worst-case, since the benchmarking logic extrapolates. They
	/// should be a bit more than usually expected.
	fn with_benchmarking_default(mut self) -> Self {
		self.max_head_data_size = self.max_head_data_size.max(1 << 20);
		self.max_downward_message_size = self.max_downward_message_size.max(1 << 16);
		self.hrmp_channel_max_capacity = self.hrmp_channel_max_capacity.max(1000);
		self.hrmp_channel_max_message_size = self.hrmp_channel_max_message_size.max(1 << 16);
		self.hrmp_max_parachain_inbound_channels =
			self.hrmp_max_parachain_inbound_channels.max(100);
		self.hrmp_max_parachain_outbound_channels =
			self.hrmp_max_parachain_outbound_channels.max(100);
		self
	}
}

/// Enumerates the possible inconsistencies of `HostConfiguration`.
#[derive(Debug)]
pub enum InconsistentError<BlockNumber> {
	/// `group_rotation_frequency` is set to zero.
	ZeroGroupRotationFrequency,
	/// `paras_availability_period` is set to zero.
	ZeroParasAvailabilityPeriod,
	/// `no_show_slots` is set to zero.
	ZeroNoShowSlots,
	/// `max_code_size` exceeds the hard limit of `MAX_CODE_SIZE`.
	MaxCodeSizeExceedHardLimit { max_code_size: u32 },
	/// `max_head_data_size` exceeds the hard limit of `MAX_HEAD_DATA_SIZE`.
	MaxHeadDataSizeExceedHardLimit { max_head_data_size: u32 },
	/// `max_pov_size` exceeds the hard limit of `POV_SIZE_HARD_LIMIT`.
	MaxPovSizeExceedHardLimit { max_pov_size: u32 },
	/// `minimum_validation_upgrade_delay` is less than `paras_availability_period`.
	MinimumValidationUpgradeDelayLessThanChainAvailabilityPeriod {
		minimum_validation_upgrade_delay: BlockNumber,
		paras_availability_period: BlockNumber,
	},
	/// `validation_upgrade_delay` is less than or equal 1.
	ValidationUpgradeDelayIsTooLow { validation_upgrade_delay: BlockNumber },
	/// Maximum UMP message size
	/// ([`MAX_UPWARD_MESSAGE_SIZE_BOUND`](crate::inclusion::MAX_UPWARD_MESSAGE_SIZE_BOUND))
	/// exceeded.
	MaxUpwardMessageSizeExceeded { max_message_size: u32 },
	/// Maximum HRMP message num ([`MAX_HORIZONTAL_MESSAGE_NUM`]) exceeded.
	MaxHorizontalMessageNumExceeded { max_message_num: u32 },
	/// Maximum UMP message num ([`MAX_UPWARD_MESSAGE_NUM`]) exceeded.
	MaxUpwardMessageNumExceeded { max_message_num: u32 },
	/// Maximum number of HRMP outbound channels exceeded.
	MaxHrmpOutboundChannelsExceeded,
	/// Maximum number of HRMP inbound channels exceeded.
	MaxHrmpInboundChannelsExceeded,
	/// `minimum_backing_votes` is set to zero.
	ZeroMinimumBackingVotes,
	/// `executor_params` are inconsistent.
	InconsistentExecutorParams { inner: ExecutorParamError },
	/// Lookahead is zero, while it must be at least 1 for parachains to work.
	LookaheadZero,
	/// Passed in queue size for on-demand was too large.
	OnDemandQueueSizeTooLarge,
	/// Number of delay tranches cannot be 0.
	ZeroDelayTranches,
}

impl<BlockNumber> HostConfiguration<BlockNumber>
where
	BlockNumber: Zero + PartialOrd + core::fmt::Debug + Clone + From<u32>,
{
	/// Checks that this instance is consistent with the requirements on each individual member.
	///
	/// # Errors
	///
	/// This function returns an error if the configuration is inconsistent.
	pub fn check_consistency(&self) -> Result<(), InconsistentError<BlockNumber>> {
		use InconsistentError::*;

		if self.scheduler_params.group_rotation_frequency.is_zero() {
			return Err(ZeroGroupRotationFrequency)
		}

		if self.scheduler_params.paras_availability_period.is_zero() {
			return Err(ZeroParasAvailabilityPeriod)
		}

		if self.no_show_slots.is_zero() {
			return Err(ZeroNoShowSlots)
		}

		if self.max_code_size > MAX_CODE_SIZE {
			return Err(MaxCodeSizeExceedHardLimit { max_code_size: self.max_code_size })
		}

		if self.max_head_data_size > MAX_HEAD_DATA_SIZE {
			return Err(MaxHeadDataSizeExceedHardLimit {
				max_head_data_size: self.max_head_data_size,
			})
		}

		if self.max_pov_size > POV_SIZE_HARD_LIMIT {
			return Err(MaxPovSizeExceedHardLimit { max_pov_size: self.max_pov_size })
		}

		if self.minimum_validation_upgrade_delay <= self.scheduler_params.paras_availability_period
		{
			return Err(MinimumValidationUpgradeDelayLessThanChainAvailabilityPeriod {
				minimum_validation_upgrade_delay: self.minimum_validation_upgrade_delay.clone(),
				paras_availability_period: self.scheduler_params.paras_availability_period.clone(),
			})
		}

		if self.validation_upgrade_delay <= 1.into() {
			return Err(ValidationUpgradeDelayIsTooLow {
				validation_upgrade_delay: self.validation_upgrade_delay.clone(),
			})
		}

		if self.max_upward_message_size > crate::inclusion::MAX_UPWARD_MESSAGE_SIZE_BOUND {
			return Err(MaxUpwardMessageSizeExceeded {
				max_message_size: self.max_upward_message_size,
			})
		}

		if self.hrmp_max_message_num_per_candidate > MAX_HORIZONTAL_MESSAGE_NUM {
			return Err(MaxHorizontalMessageNumExceeded {
				max_message_num: self.hrmp_max_message_num_per_candidate,
			})
		}

		if self.max_upward_message_num_per_candidate > MAX_UPWARD_MESSAGE_NUM {
			return Err(MaxUpwardMessageNumExceeded {
				max_message_num: self.max_upward_message_num_per_candidate,
			})
		}

		if self.hrmp_max_parachain_outbound_channels > crate::hrmp::HRMP_MAX_OUTBOUND_CHANNELS_BOUND
		{
			return Err(MaxHrmpOutboundChannelsExceeded)
		}

		if self.hrmp_max_parachain_inbound_channels > crate::hrmp::HRMP_MAX_INBOUND_CHANNELS_BOUND {
			return Err(MaxHrmpInboundChannelsExceeded)
		}

		if self.minimum_backing_votes.is_zero() {
			return Err(ZeroMinimumBackingVotes)
		}

		if let Err(inner) = self.executor_params.check_consistency() {
			return Err(InconsistentExecutorParams { inner })
		}

		if self.scheduler_params.lookahead == 0 {
			return Err(LookaheadZero)
		}

		if self.scheduler_params.on_demand_queue_max_size > ON_DEMAND_MAX_QUEUE_MAX_SIZE {
			return Err(OnDemandQueueSizeTooLarge)
		}

		if self.n_delay_tranches.is_zero() {
			return Err(ZeroDelayTranches)
		}

		Ok(())
	}

	/// Checks that this instance is consistent with the requirements on each individual member.
	///
	/// # Panics
	///
	/// This function panics if the configuration is inconsistent.
	pub fn panic_if_not_consistent(&self) {
		if let Err(err) = self.check_consistency() {
			panic!("Host configuration is inconsistent: {:?}\nCfg:\n{:#?}", err, self);
		}
	}
}

pub trait WeightInfo {
	fn set_config_with_block_number() -> Weight;
	fn set_config_with_u32() -> Weight;
	fn set_config_with_option_u32() -> Weight;
	fn set_config_with_balance() -> Weight;
	fn set_hrmp_open_request_ttl() -> Weight;
	fn set_config_with_executor_params() -> Weight;
	fn set_config_with_perbill() -> Weight;
	fn set_node_feature() -> Weight;
	fn set_config_with_scheduler_params() -> Weight;
}

pub struct TestWeightInfo;
impl WeightInfo for TestWeightInfo {
	fn set_config_with_block_number() -> Weight {
		Weight::MAX
	}
	fn set_config_with_u32() -> Weight {
		Weight::MAX
	}
	fn set_config_with_option_u32() -> Weight {
		Weight::MAX
	}
	fn set_config_with_balance() -> Weight {
		Weight::MAX
	}
	fn set_hrmp_open_request_ttl() -> Weight {
		Weight::MAX
	}
	fn set_config_with_executor_params() -> Weight {
		Weight::MAX
	}
	fn set_config_with_perbill() -> Weight {
		Weight::MAX
	}
	fn set_node_feature() -> Weight {
		Weight::MAX
	}
	fn set_config_with_scheduler_params() -> Weight {
		Weight::MAX
	}
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;

	/// The in-code storage version.
	///
	/// v0-v1:  <https://github.com/paritytech/polkadot/pull/3575>
	/// v1-v2:  <https://github.com/paritytech/polkadot/pull/4420>
	/// v2-v3:  <https://github.com/paritytech/polkadot/pull/6091>
	/// v3-v4:  <https://github.com/paritytech/polkadot/pull/6345>
	/// v4-v5:  <https://github.com/paritytech/polkadot/pull/6937>
	///       + <https://github.com/paritytech/polkadot/pull/6961>
	///       + <https://github.com/paritytech/polkadot/pull/6934>
	/// v5-v6:  <https://github.com/paritytech/polkadot/pull/6271> (remove UMP dispatch queue)
	/// v6-v7:  <https://github.com/paritytech/polkadot/pull/7396>
	/// v7-v8:  <https://github.com/paritytech/polkadot/pull/6969>
	/// v8-v9:  <https://github.com/paritytech/polkadot/pull/7577>
	/// v9-v10: <https://github.com/paritytech/polkadot-sdk/pull/2177>
	/// v10-11: <https://github.com/paritytech/polkadot-sdk/pull/1191>
	/// v11-12: <https://github.com/paritytech/polkadot-sdk/pull/3181>
	const STORAGE_VERSION: StorageVersion = StorageVersion::new(12);

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config + shared::Config {
		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The new value for a configuration parameter is invalid.
		InvalidNewValue,
	}

	/// The active configuration for the current session.
	#[pallet::storage]
	#[pallet::whitelist_storage]
	pub type ActiveConfig<T: Config> =
		StorageValue<_, HostConfiguration<BlockNumberFor<T>>, ValueQuery>;

	/// Pending configuration changes.
	///
	/// This is a list of configuration changes, each with a session index at which it should
	/// be applied.
	///
	/// The list is sorted ascending by session index. Also, this list can only contain at most
	/// 2 items: for the next session and for the `scheduled_session`.
	#[pallet::storage]
	pub type PendingConfigs<T: Config> =
		StorageValue<_, Vec<(SessionIndex, HostConfiguration<BlockNumberFor<T>>)>, ValueQuery>;

	/// If this is set, then the configuration setters will bypass the consistency checks. This
	/// is meant to be used only as the last resort.
	#[pallet::storage]
	pub(crate) type BypassConsistencyCheck<T: Config> = StorageValue<_, bool, ValueQuery>;

	#[pallet::genesis_config]
	#[derive(DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub config: HostConfiguration<BlockNumberFor<T>>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			self.config.panic_if_not_consistent();
			ActiveConfig::<T>::put(&self.config);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Set the validation upgrade cooldown.
		#[pallet::call_index(0)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_block_number(),
			DispatchClass::Operational,
		))]
		pub fn set_validation_upgrade_cooldown(
			origin: OriginFor<T>,
			new: BlockNumberFor<T>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.validation_upgrade_cooldown = new;
			})
		}

		/// Set the validation upgrade delay.
		#[pallet::call_index(1)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_block_number(),
			DispatchClass::Operational,
		))]
		pub fn set_validation_upgrade_delay(
			origin: OriginFor<T>,
			new: BlockNumberFor<T>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.validation_upgrade_delay = new;
			})
		}

		/// Set the acceptance period for an included candidate.
		#[pallet::call_index(2)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_block_number(),
			DispatchClass::Operational,
		))]
		pub fn set_code_retention_period(
			origin: OriginFor<T>,
			new: BlockNumberFor<T>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.code_retention_period = new;
			})
		}

		/// Set the max validation code size for incoming upgrades.
		#[pallet::call_index(3)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_max_code_size(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.max_code_size = new;
			})
		}

		/// Set the max POV block size for incoming upgrades.
		#[pallet::call_index(4)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_max_pov_size(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.max_pov_size = new;
			})
		}

		/// Set the max head data size for paras.
		#[pallet::call_index(5)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_max_head_data_size(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.max_head_data_size = new;
			})
		}

		/// Set the number of coretime execution cores.
		///
		/// NOTE: that this configuration is managed by the coretime chain. Only manually change
		/// this, if you really know what you are doing!
		#[pallet::call_index(6)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_coretime_cores(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::set_coretime_cores_unchecked(new)
		}

		// Call index 7 used to be `set_max_availability_timeouts`, which was removed.

		/// Set the parachain validator-group rotation frequency
		#[pallet::call_index(8)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_block_number(),
			DispatchClass::Operational,
		))]
		pub fn set_group_rotation_frequency(
			origin: OriginFor<T>,
			new: BlockNumberFor<T>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.scheduler_params.group_rotation_frequency = new;
			})
		}

		/// Set the availability period for paras.
		#[pallet::call_index(9)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_block_number(),
			DispatchClass::Operational,
		))]
		pub fn set_paras_availability_period(
			origin: OriginFor<T>,
			new: BlockNumberFor<T>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.scheduler_params.paras_availability_period = new;
			})
		}

		/// Set the scheduling lookahead, in expected number of blocks at peak throughput.
		#[pallet::call_index(11)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_scheduling_lookahead(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.scheduler_params.lookahead = new;
			})
		}

		/// Set the maximum number of validators to assign to any core.
		#[pallet::call_index(12)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_option_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_max_validators_per_core(
			origin: OriginFor<T>,
			new: Option<u32>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.scheduler_params.max_validators_per_core = new;
			})
		}

		/// Set the maximum number of validators to use in parachain consensus.
		#[pallet::call_index(13)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_option_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_max_validators(origin: OriginFor<T>, new: Option<u32>) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.max_validators = new;
			})
		}

		/// Set the dispute period, in number of sessions to keep for disputes.
		#[pallet::call_index(14)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_dispute_period(origin: OriginFor<T>, new: SessionIndex) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.dispute_period = new;
			})
		}

		/// Set the dispute post conclusion acceptance period.
		#[pallet::call_index(15)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_block_number(),
			DispatchClass::Operational,
		))]
		pub fn set_dispute_post_conclusion_acceptance_period(
			origin: OriginFor<T>,
			new: BlockNumberFor<T>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.dispute_post_conclusion_acceptance_period = new;
			})
		}

		/// Set the no show slots, in number of number of consensus slots.
		/// Must be at least 1.
		#[pallet::call_index(18)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_no_show_slots(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.no_show_slots = new;
			})
		}

		/// Set the total number of delay tranches.
		#[pallet::call_index(19)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_n_delay_tranches(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.n_delay_tranches = new;
			})
		}

		/// Set the zeroth delay tranche width.
		#[pallet::call_index(20)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_zeroth_delay_tranche_width(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.zeroth_delay_tranche_width = new;
			})
		}

		/// Set the number of validators needed to approve a block.
		#[pallet::call_index(21)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_needed_approvals(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.needed_approvals = new;
			})
		}

		/// Set the number of samples to do of the `RelayVRFModulo` approval assignment criterion.
		#[pallet::call_index(22)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_relay_vrf_modulo_samples(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.relay_vrf_modulo_samples = new;
			})
		}

		/// Sets the maximum items that can present in a upward dispatch queue at once.
		#[pallet::call_index(23)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_max_upward_queue_count(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.max_upward_queue_count = new;
			})
		}

		/// Sets the maximum total size of items that can present in a upward dispatch queue at
		/// once.
		#[pallet::call_index(24)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_max_upward_queue_size(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;

			Self::schedule_config_update(|config| {
				config.max_upward_queue_size = new;
			})
		}

		/// Set the critical downward message size.
		#[pallet::call_index(25)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_max_downward_message_size(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.max_downward_message_size = new;
			})
		}

		/// Sets the maximum size of an upward message that can be sent by a candidate.
		#[pallet::call_index(27)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_max_upward_message_size(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.max_upward_message_size = new;
			})
		}

		/// Sets the maximum number of messages that a candidate can contain.
		#[pallet::call_index(28)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_max_upward_message_num_per_candidate(
			origin: OriginFor<T>,
			new: u32,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.max_upward_message_num_per_candidate = new;
			})
		}

		/// Sets the number of sessions after which an HRMP open channel request expires.
		#[pallet::call_index(29)]
		#[pallet::weight((
			T::WeightInfo::set_hrmp_open_request_ttl(),
			DispatchClass::Operational,
		))]
		// Deprecated, but is not marked as such, because that would trigger warnings coming from
		// the macro.
		pub fn set_hrmp_open_request_ttl(_origin: OriginFor<T>, _new: u32) -> DispatchResult {
			Err("this doesn't have any effect".into())
		}

		/// Sets the amount of funds that the sender should provide for opening an HRMP channel.
		#[pallet::call_index(30)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_balance(),
			DispatchClass::Operational,
		))]
		pub fn set_hrmp_sender_deposit(origin: OriginFor<T>, new: Balance) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.hrmp_sender_deposit = new;
			})
		}

		/// Sets the amount of funds that the recipient should provide for accepting opening an HRMP
		/// channel.
		#[pallet::call_index(31)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_balance(),
			DispatchClass::Operational,
		))]
		pub fn set_hrmp_recipient_deposit(origin: OriginFor<T>, new: Balance) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.hrmp_recipient_deposit = new;
			})
		}

		/// Sets the maximum number of messages allowed in an HRMP channel at once.
		#[pallet::call_index(32)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_hrmp_channel_max_capacity(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.hrmp_channel_max_capacity = new;
			})
		}

		/// Sets the maximum total size of messages in bytes allowed in an HRMP channel at once.
		#[pallet::call_index(33)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_hrmp_channel_max_total_size(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.hrmp_channel_max_total_size = new;
			})
		}

		/// Sets the maximum number of inbound HRMP channels a parachain is allowed to accept.
		#[pallet::call_index(34)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_hrmp_max_parachain_inbound_channels(
			origin: OriginFor<T>,
			new: u32,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.hrmp_max_parachain_inbound_channels = new;
			})
		}

		/// Sets the maximum size of a message that could ever be put into an HRMP channel.
		#[pallet::call_index(36)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_hrmp_channel_max_message_size(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.hrmp_channel_max_message_size = new;
			})
		}

		/// Sets the maximum number of outbound HRMP channels a parachain is allowed to open.
		#[pallet::call_index(37)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_hrmp_max_parachain_outbound_channels(
			origin: OriginFor<T>,
			new: u32,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.hrmp_max_parachain_outbound_channels = new;
			})
		}

		/// Sets the maximum number of outbound HRMP messages can be sent by a candidate.
		#[pallet::call_index(39)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_hrmp_max_message_num_per_candidate(
			origin: OriginFor<T>,
			new: u32,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.hrmp_max_message_num_per_candidate = new;
			})
		}

		/// Set the number of session changes after which a PVF pre-checking voting is rejected.
		#[pallet::call_index(42)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_pvf_voting_ttl(origin: OriginFor<T>, new: SessionIndex) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.pvf_voting_ttl = new;
			})
		}

		/// Sets the minimum delay between announcing the upgrade block for a parachain until the
		/// upgrade taking place.
		///
		/// See the field documentation for information and constraints for the new value.
		#[pallet::call_index(43)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_block_number(),
			DispatchClass::Operational,
		))]
		pub fn set_minimum_validation_upgrade_delay(
			origin: OriginFor<T>,
			new: BlockNumberFor<T>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.minimum_validation_upgrade_delay = new;
			})
		}

		/// Setting this to true will disable consistency checks for the configuration setters.
		/// Use with caution.
		#[pallet::call_index(44)]
		#[pallet::weight((
			T::DbWeight::get().writes(1),
			DispatchClass::Operational,
		))]
		pub fn set_bypass_consistency_check(origin: OriginFor<T>, new: bool) -> DispatchResult {
			ensure_root(origin)?;
			BypassConsistencyCheck::<T>::put(new);
			Ok(())
		}

		/// Set the asynchronous backing parameters.
		#[pallet::call_index(45)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_option_u32(), // The same size in bytes.
			DispatchClass::Operational,
		))]
		pub fn set_async_backing_params(
			origin: OriginFor<T>,
			new: AsyncBackingParams,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.async_backing_params = new;
			})
		}

		/// Set PVF executor parameters.
		#[pallet::call_index(46)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_executor_params(),
			DispatchClass::Operational,
		))]
		pub fn set_executor_params(origin: OriginFor<T>, new: ExecutorParams) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.executor_params = new;
			})
		}

		/// Set the on demand (parathreads) base fee.
		#[pallet::call_index(47)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_balance(),
			DispatchClass::Operational,
		))]
		pub fn set_on_demand_base_fee(origin: OriginFor<T>, new: Balance) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.scheduler_params.on_demand_base_fee = new;
			})
		}

		/// Set the on demand (parathreads) fee variability.
		#[pallet::call_index(48)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_perbill(),
			DispatchClass::Operational,
		))]
		pub fn set_on_demand_fee_variability(origin: OriginFor<T>, new: Perbill) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.scheduler_params.on_demand_fee_variability = new;
			})
		}

		/// Set the on demand (parathreads) queue max size.
		#[pallet::call_index(49)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_option_u32(),
			DispatchClass::Operational,
		))]
		pub fn set_on_demand_queue_max_size(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.scheduler_params.on_demand_queue_max_size = new;
			})
		}

		/// Set the on demand (parathreads) fee variability.
		#[pallet::call_index(50)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_perbill(),
			DispatchClass::Operational,
		))]
		pub fn set_on_demand_target_queue_utilization(
			origin: OriginFor<T>,
			new: Perbill,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.scheduler_params.on_demand_target_queue_utilization = new;
			})
		}

		// Call index 51 used to be `set_on_demand_ttl`, which was removed.

		/// Set the minimum backing votes threshold.
		#[pallet::call_index(52)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_u32(),
			DispatchClass::Operational
		))]
		pub fn set_minimum_backing_votes(origin: OriginFor<T>, new: u32) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.minimum_backing_votes = new;
			})
		}

		/// Set/Unset a node feature.
		#[pallet::call_index(53)]
		#[pallet::weight((
			T::WeightInfo::set_node_feature(),
			DispatchClass::Operational
		))]
		pub fn set_node_feature(origin: OriginFor<T>, index: u8, value: bool) -> DispatchResult {
			ensure_root(origin)?;

			Self::schedule_config_update(|config| {
				let index = usize::from(index);
				if config.node_features.len() <= index {
					config.node_features.resize(index + 1, false);
				}
				config.node_features.set(index, value);
			})
		}

		/// Set approval-voting-params.
		#[pallet::call_index(54)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_executor_params(),
			DispatchClass::Operational,
		))]
		pub fn set_approval_voting_params(
			origin: OriginFor<T>,
			new: ApprovalVotingParams,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.approval_voting_params = new;
			})
		}

		/// Set scheduler-params.
		#[pallet::call_index(55)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_scheduler_params(),
			DispatchClass::Operational,
		))]
		pub fn set_scheduler_params(
			origin: OriginFor<T>,
			new: SchedulerParams<BlockNumberFor<T>>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.scheduler_params = new;
			})
		}
	}

	impl<T: Config> Pallet<T> {
		/// Set coretime cores.
		///
		/// To be used if authorization is checked otherwise.
		pub fn set_coretime_cores_unchecked(new: u32) -> DispatchResult {
			Self::schedule_config_update(|config| {
				config.scheduler_params.num_cores = new;
			})
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn integrity_test() {
			assert_eq!(
				&ActiveConfig::<T>::hashed_key(),
				polkadot_primitives::well_known_keys::ACTIVE_CONFIG,
				"`well_known_keys::ACTIVE_CONFIG` doesn't match key of `ActiveConfig`! Make sure that the name of the\
				 configuration pallet is `Configuration` in the runtime!",
			);
		}
	}
}

/// A struct that holds the configuration that was active before the session change and optionally
/// a configuration that became active after the session change.
pub struct SessionChangeOutcome<BlockNumber> {
	/// Previously active configuration.
	pub prev_config: HostConfiguration<BlockNumber>,
	/// If new configuration was applied during the session change, this is the new configuration.
	pub new_config: Option<HostConfiguration<BlockNumber>>,
}

impl<T: Config> Pallet<T> {
	/// Called by the initializer to initialize the configuration pallet.
	pub(crate) fn initializer_initialize(_now: BlockNumberFor<T>) -> Weight {
		Weight::zero()
	}

	/// Called by the initializer to finalize the configuration pallet.
	pub(crate) fn initializer_finalize() {}

	/// Called by the initializer to note that a new session has started.
	///
	/// Returns the configuration that was actual before the session change and the configuration
	/// that became active after the session change. If there were no scheduled changes, both will
	/// be the same.
	pub(crate) fn initializer_on_new_session(
		session_index: &SessionIndex,
	) -> SessionChangeOutcome<BlockNumberFor<T>> {
		let pending_configs = PendingConfigs::<T>::get();
		let prev_config = ActiveConfig::<T>::get();

		// No pending configuration changes, so we're done.
		if pending_configs.is_empty() {
			return SessionChangeOutcome { prev_config, new_config: None }
		}

		let (mut past_and_present, future) = pending_configs
			.into_iter()
			.partition::<Vec<_>, _>(|&(apply_at_session, _)| apply_at_session <= *session_index);

		if past_and_present.len() > 1 {
			// This should never happen since we schedule configuration changes only into the future
			// sessions and this handler called for each session change.
			log::error!(
				target: LOG_TARGET,
				"Skipping applying configuration changes scheduled sessions in the past",
			);
		}

		let new_config = past_and_present.pop().map(|(_, config)| config);
		if let Some(ref new_config) = new_config {
			// Apply the new configuration.
			ActiveConfig::<T>::put(new_config);
		}

		PendingConfigs::<T>::put(future);

		SessionChangeOutcome { prev_config, new_config }
	}

	/// Return the session index that should be used for any future scheduled changes.
	fn scheduled_session() -> SessionIndex {
		shared::Pallet::<T>::scheduled_session()
	}

	/// Forcibly set the active config. This should be used with extreme care, and typically
	/// only when enabling parachains runtime pallets for the first time on a chain which has
	/// been running without them.
	pub fn force_set_active_config(config: HostConfiguration<BlockNumberFor<T>>) {
		ActiveConfig::<T>::set(config);
	}

	/// This function should be used to update members of the configuration.
	///
	/// This function is used to update the configuration in a way that is safe. It will check the
	/// resulting configuration and ensure that the update is valid. If the update is invalid, it
	/// will check if the previous configuration was valid. If it was invalid, we proceed with
	/// updating the configuration, giving a chance to recover from such a condition.
	///
	/// The actual configuration change takes place after a couple of sessions have passed. In case
	/// this function is called more than once in the same session, then the pending configuration
	/// change will be updated.
	/// In other words, all the configuration changes made in the same session will be folded
	/// together in the order they were made, and only once the scheduled session is reached will
	/// the final pending configuration be applied.
	// NOTE: Explicitly tell rustc not to inline this, because otherwise heuristics note the
	// incoming closure make it attractive to inline. However, in that case, we will end up with
	// lots of duplicated code (making this function show up on top of the heaviest functions) only
	// for the sake of essentially avoiding an indirect call. It is not worth it.
	#[inline(never)]
	pub(crate) fn schedule_config_update(
		updater: impl FnOnce(&mut HostConfiguration<BlockNumberFor<T>>),
	) -> DispatchResult {
		let mut pending_configs = PendingConfigs::<T>::get();

		// 1. pending_configs = [] No pending configuration changes.
		//
		//    That means we should use the active config as the base configuration. We will insert
		//    the new pending configuration as (cur+2, new_config) into the list.
		//
		// 2. pending_configs = [(cur+2, X)] There is a configuration that is pending for the
		//    scheduled session.
		//
		//    We will use X as the base configuration. We can update the pending configuration X
		//    directly.
		//
		// 3. pending_configs = [(cur+1, X)] There is a pending configuration scheduled and it will
		//    be applied in the next session.
		//
		//    We will use X as the base configuration. We need to schedule a new configuration
		// change    for the `scheduled_session` and use X as the base for the new configuration.
		//
		// 4. pending_configs = [(cur+1, X), (cur+2, Y)] There is a pending configuration change in
		//    the next session and for the scheduled session. Due to case №3, we can be sure that Y
		//    is based on top of X. This means we can use Y as the base configuration and update Y
		//    directly.
		//
		// There cannot be (cur, X) because those are applied in the session change handler for the
		// current session.

		// First, we need to decide what we should use as the base configuration.
		let mut base_config = pending_configs
			.last()
			.map(|(_, config)| config.clone())
			.unwrap_or_else(ActiveConfig::<T>::get);
		let base_config_consistent = base_config.check_consistency().is_ok();

		// Now, we need to decide what the new configuration should be.
		// We also move the `base_config` to `new_config` to emphasize that the base config was
		// destroyed by the `updater`.
		updater(&mut base_config);
		let new_config = base_config;

		if BypassConsistencyCheck::<T>::get() {
			// This will emit a warning each configuration update if the consistency check is
			// bypassed. This is an attempt to make sure the bypass is not accidentally left on.
			log::warn!(
				target: LOG_TARGET,
				"Bypassing the consistency check for the configuration change!",
			);
		} else if let Err(e) = new_config.check_consistency() {
			if base_config_consistent {
				// Base configuration is consistent and the new configuration is inconsistent.
				// This means that the value set by the `updater` is invalid and we can return
				// it as an error.
				log::warn!(
					target: LOG_TARGET,
					"Configuration change rejected due to invalid configuration: {:?}",
					e,
				);
				return Err(Error::<T>::InvalidNewValue.into())
			} else {
				// The configuration was already broken, so we can as well proceed with the update.
				// You cannot break something that is already broken.
				//
				// That will allow to call several functions and ultimately return the configuration
				// into consistent state.
				log::warn!(
					target: LOG_TARGET,
					"The new configuration is broken but the old is broken as well. Proceeding",
				);
			}
		}

		let scheduled_session = Self::scheduled_session();

		if let Some(&mut (_, ref mut config)) = pending_configs
			.iter_mut()
			.find(|&&mut (apply_at_session, _)| apply_at_session >= scheduled_session)
		{
			*config = new_config;
		} else {
			// We are scheduling a new configuration change for the scheduled session.
			pending_configs.push((scheduled_session, new_config));
		}

		PendingConfigs::<T>::put(pending_configs);

		Ok(())
	}
}

/// The implementation of `Get<(u32, u32)>` which reads `ActiveConfig` and returns `P` percent of
/// `hrmp_channel_max_message_size` / `hrmp_channel_max_capacity`.
pub struct ActiveConfigHrmpChannelSizeAndCapacityRatio<T, P>(core::marker::PhantomData<(T, P)>);
impl<T: crate::hrmp::pallet::Config, P: Get<Percent>> Get<(u32, u32)>
	for ActiveConfigHrmpChannelSizeAndCapacityRatio<T, P>
{
	fn get() -> (u32, u32) {
		let config = ActiveConfig::<T>::get();
		let percent = P::get();
		(percent * config.hrmp_channel_max_message_size, percent * config.hrmp_channel_max_capacity)
	}
}
