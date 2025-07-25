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

//! # Overseer
//!
//! `overseer` implements the Overseer architecture described in the
//! [implementers' guide][overseer-page].
//! For the motivations behind implementing the overseer itself you should
//! check out that guide, documentation in this crate will be mostly discussing
//! technical stuff.
//!
//! An `Overseer` is something that allows spawning/stopping and overseeing
//! asynchronous tasks as well as establishing a well-defined and easy to use
//! protocol that the tasks can use to communicate with each other. It is desired
//! that this protocol is the only way tasks communicate with each other, however
//! at this moment there are no foolproof guards against other ways of communication.
//!
//! The `Overseer` is instantiated with a pre-defined set of `Subsystems` that
//! share the same behavior from `Overseer`'s point of view.
//!
//! ```text
//!                              +-----------------------------+
//!                              |         Overseer            |
//!                              +-----------------------------+
//!
//!             ................|  Overseer "holds" these and uses |..............
//!             .                  them to (re)start things                      .
//!             .                                                                .
//!             .  +-------------------+                +---------------------+  .
//!             .  |   Subsystem1      |                |   Subsystem2        |  .
//!             .  +-------------------+                +---------------------+  .
//!             .           |                                       |            .
//!             ..................................................................
//!                         |                                       |
//!                       start()                                 start()
//!                         V                                       V
//!             ..................| Overseer "runs" these |.......................
//!             .  +--------------------+               +---------------------+  .
//!             .  | SubsystemInstance1 |               | SubsystemInstance2  |  .
//!             .  +--------------------+               +---------------------+  .
//!             ..................................................................
//! ```
//!
//! [overseer-page]: https://paritytech.github.io/polkadot-sdk/book/node/overseer.html

// #![deny(unused_results)]
// unused dependencies can not work for test and examples at the same time
// yielding false positives
#![warn(missing_docs)]
// TODO https://github.com/paritytech/polkadot-sdk/issues/5793
#![allow(dead_code, irrefutable_let_patterns)]

use std::{
	collections::{hash_map, HashMap},
	fmt::{self, Debug},
	pin::Pin,
	sync::Arc,
	time::Duration,
};

use futures::{channel::oneshot, future::BoxFuture, select, Future, FutureExt, StreamExt};

use polkadot_primitives::{Block, BlockNumber, Hash};
use sc_client_api::{BlockImportNotification, BlockchainEvents, FinalityNotification};

use self::messages::{BitfieldSigningMessage, PvfCheckerMessage};
use polkadot_node_subsystem_types::messages::{
	ApprovalDistributionMessage, ApprovalVotingMessage, ApprovalVotingParallelMessage,
	AvailabilityDistributionMessage, AvailabilityRecoveryMessage, AvailabilityStoreMessage,
	BitfieldDistributionMessage, CandidateBackingMessage, CandidateValidationMessage,
	ChainApiMessage, ChainSelectionMessage, CollationGenerationMessage, CollatorProtocolMessage,
	DisputeCoordinatorMessage, DisputeDistributionMessage, GossipSupportMessage,
	NetworkBridgeRxMessage, NetworkBridgeTxMessage, ProspectiveParachainsMessage,
	ProvisionerMessage, RuntimeApiMessage, StatementDistributionMessage,
};

pub use polkadot_node_subsystem_types::{
	errors::{SubsystemError, SubsystemResult},
	ActivatedLeaf, ActiveLeavesUpdate, ChainApiBackend, OverseerSignal, RuntimeApiSubsystemClient,
	UnpinHandle,
};

pub mod metrics;
pub use self::metrics::Metrics as OverseerMetrics;

/// A dummy subsystem, mostly useful for placeholders and tests.
pub mod dummy;
pub use self::dummy::DummySubsystem;

pub use polkadot_node_metrics::{
	metrics::{prometheus, Metrics as MetricsTrait},
	Metronome,
};

pub use orchestra as gen;
pub use orchestra::{
	contextbounds, orchestra, subsystem, FromOrchestra, HighPriority, MapSubsystem, MessagePacket,
	NormalPriority, OrchestraError as OverseerError, Priority, PriorityLevel, SignalsReceived,
	Spawner, Subsystem, SubsystemContext, SubsystemIncomingMessages, SubsystemInstance,
	SubsystemMeterReadouts, SubsystemMeters, SubsystemSender, TimeoutExt, ToOrchestra,
	TrySendError,
};

#[cfg(any(target_os = "linux", feature = "jemalloc-allocator"))]
mod memory_stats;
#[cfg(test)]
mod tests;

use sp_core::traits::SpawnNamed;

/// Glue to connect `trait orchestra::Spawner` and `SpawnNamed` from `substrate`.
pub struct SpawnGlue<S>(pub S);

impl<S> AsRef<S> for SpawnGlue<S> {
	fn as_ref(&self) -> &S {
		&self.0
	}
}

impl<S: Clone> Clone for SpawnGlue<S> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

impl<S: SpawnNamed + Clone + Send + Sync> crate::gen::Spawner for SpawnGlue<S> {
	fn spawn_blocking(
		&self,
		name: &'static str,
		group: Option<&'static str>,
		future: futures::future::BoxFuture<'static, ()>,
	) {
		SpawnNamed::spawn_blocking(&self.0, name, group, future)
	}
	fn spawn(
		&self,
		name: &'static str,
		group: Option<&'static str>,
		future: futures::future::BoxFuture<'static, ()>,
	) {
		SpawnNamed::spawn(&self.0, name, group, future)
	}
}

/// Whether a header supports parachain consensus or not.
#[async_trait::async_trait]
pub trait HeadSupportsParachains {
	/// Return true if the given header supports parachain consensus. Otherwise, false.
	async fn head_supports_parachains(&self, head: &Hash) -> bool;
}

#[async_trait::async_trait]
impl<Client> HeadSupportsParachains for Arc<Client>
where
	Client: RuntimeApiSubsystemClient + Sync + Send,
{
	async fn head_supports_parachains(&self, head: &Hash) -> bool {
		// Check that the `ParachainHost` runtime api is at least with version 1 present on chain.
		self.api_version_parachain_host(*head).await.ok().flatten().unwrap_or(0) >= 1
	}
}

/// A handle used to communicate with the [`Overseer`].
///
/// [`Overseer`]: struct.Overseer.html
#[derive(Clone)]
pub struct Handle(OverseerHandle);

impl Handle {
	/// Create a new [`Handle`].
	pub fn new(raw: OverseerHandle) -> Self {
		Self(raw)
	}

	/// Inform the `Overseer` that that some block was imported.
	pub async fn block_imported(&mut self, block: BlockInfo) {
		self.send_and_log_error(Event::BlockImported(block)).await
	}

	/// Send some message with normal priority to one of the `Subsystem`s.
	pub async fn send_msg(&mut self, msg: impl Into<AllMessages>, origin: &'static str) {
		self.send_msg_with_priority(msg, origin, PriorityLevel::Normal).await
	}

	/// Send some message with the specified priority to one of the `Subsystem`s.
	pub async fn send_msg_with_priority(
		&mut self,
		msg: impl Into<AllMessages>,
		origin: &'static str,
		priority: PriorityLevel,
	) {
		self.send_and_log_error(Event::MsgToSubsystem { msg: msg.into(), origin, priority })
			.await
	}

	/// Send a message not providing an origin.
	#[inline(always)]
	pub async fn send_msg_anon(&mut self, msg: impl Into<AllMessages>) {
		self.send_msg(msg, "").await
	}

	/// Inform the `Overseer` that some block was finalized.
	pub async fn block_finalized(&mut self, block: BlockInfo) {
		self.send_and_log_error(Event::BlockFinalized(block)).await
	}

	/// Wait for a block with the given hash to be in the active-leaves set.
	///
	/// The response channel responds if the hash was activated and is closed if the hash was
	/// deactivated. Note that due the fact the overseer doesn't store the whole active-leaves set,
	/// only deltas, the response channel may never return if the hash was deactivated before this
	/// call. In this case, it's the caller's responsibility to ensure a timeout is set.
	pub async fn wait_for_activation(
		&mut self,
		hash: Hash,
		response_channel: oneshot::Sender<SubsystemResult<()>>,
	) {
		self.send_and_log_error(Event::ExternalRequest(ExternalRequest::WaitForActivation {
			hash,
			response_channel,
		}))
		.await;
	}

	/// Tell `Overseer` to shutdown.
	pub async fn stop(&mut self) {
		self.send_and_log_error(Event::Stop).await;
	}

	/// Most basic operation, to stop a server.
	async fn send_and_log_error(&mut self, event: Event) {
		if self.0.send(event).await.is_err() {
			gum::info!(target: LOG_TARGET, "Failed to send an event to Overseer");
		}
	}
}

/// An event telling the `Overseer` on the particular block
/// that has been imported or finalized.
///
/// This structure exists solely for the purposes of decoupling
/// `Overseer` code from the client code and the necessity to call
/// `HeaderBackend::block_number_from_id()`.
#[derive(Debug, Clone)]
pub struct BlockInfo {
	/// Hash of the block.
	pub hash: Hash,
	/// Hash of the parent block.
	pub parent_hash: Hash,
	/// Block's number.
	pub number: BlockNumber,
	/// A handle to unpin the block on drop.
	pub unpin_handle: UnpinHandle,
}

impl From<BlockImportNotification<Block>> for BlockInfo {
	fn from(n: BlockImportNotification<Block>) -> Self {
		let hash = n.hash;
		let parent_hash = n.header.parent_hash;
		let number = n.header.number;
		let unpin_handle = n.into_unpin_handle();

		BlockInfo { hash, parent_hash, number, unpin_handle }
	}
}

impl From<FinalityNotification<Block>> for BlockInfo {
	fn from(n: FinalityNotification<Block>) -> Self {
		let hash = n.hash;
		let parent_hash = n.header.parent_hash;
		let number = n.header.number;
		let unpin_handle = n.into_unpin_handle();

		BlockInfo { hash, parent_hash, number, unpin_handle }
	}
}

/// An event from outside the overseer scope, such
/// as the substrate framework or user interaction.
#[derive(Debug)]
pub enum Event {
	/// A new block was imported.
	///
	/// This event is not sent if the block was already known
	/// and we reorged to it e.g. due to a reversion.
	///
	/// Also, these events are not sent during a major sync.
	BlockImported(BlockInfo),
	/// A block was finalized with i.e. babe or another consensus algorithm.
	BlockFinalized(BlockInfo),
	/// Message as sent to a subsystem.
	MsgToSubsystem {
		/// The actual message.
		msg: AllMessages,
		/// The originating subsystem name.
		origin: &'static str,
		/// The priority of the message.
		priority: PriorityLevel,
	},
	/// A request from the outer world.
	ExternalRequest(ExternalRequest),
	/// Stop the overseer on i.e. a UNIX signal.
	Stop,
}

/// Some request from outer world.
#[derive(Debug)]
pub enum ExternalRequest {
	/// Wait for the activation of a particular hash
	/// and be notified by means of the return channel.
	WaitForActivation {
		/// The relay parent for which activation to wait for.
		hash: Hash,
		/// Response channel to await on.
		response_channel: oneshot::Sender<SubsystemResult<()>>,
	},
}

/// Glues together the [`Overseer`] and `BlockchainEvents` by forwarding
/// import and finality notifications into the [`OverseerHandle`].
pub async fn forward_events<P: BlockchainEvents<Block>>(client: Arc<P>, mut handle: Handle) {
	let mut finality = client.finality_notification_stream();
	let mut imports = client.import_notification_stream();

	loop {
		select! {
			f = finality.next() => {
				match f {
					Some(block) => {
						handle.block_finalized(block.into()).await;
					}
					None => break,
				}
			},
			i = imports.next() => {
				match i {
					Some(block) => {
						handle.block_imported(block.into()).await;
					}
					None => break,
				}
			},
			complete => break,
		}
	}
}

/// Create a new instance of the [`Overseer`] with a fixed set of [`Subsystem`]s.
///
/// This returns the overseer along with an [`OverseerHandle`] which can
/// be used to send messages from external parts of the codebase.
///
/// The [`OverseerHandle`] returned from this function is connected to
/// the returned [`Overseer`].
///
/// ```text
///                  +------------------------------------+
///                  |            Overseer                |
///                  +------------------------------------+
///                    /            |             |      \
///      ................. subsystems...................................
///      . +-----------+    +-----------+   +----------+   +---------+ .
///      . |           |    |           |   |          |   |         | .
///      . +-----------+    +-----------+   +----------+   +---------+ .
///      ...............................................................
///                              |
///                        probably `spawn`
///                            a `job`
///                              |
///                              V
///                         +-----------+
///                         |           |
///                         +-----------+
/// ```
///
/// [`Subsystem`]: trait.Subsystem.html
///
/// # Example
///
/// The [`Subsystems`] may be any type as long as they implement an expected interface.
/// Here, we create a mock validation subsystem and a few dummy ones and start the `Overseer` with
/// them. For the sake of simplicity the termination of the example is done with a timeout.
/// ```
/// # use std::time::Duration;
/// # use futures::{executor, pin_mut, select, FutureExt};
/// # use futures_timer::Delay;
/// # use polkadot_primitives::Hash;
/// # use polkadot_overseer::{
/// # 	self as overseer,
/// #   OverseerSignal,
/// # 	SubsystemSender as _,
/// # 	AllMessages,
/// # 	HeadSupportsParachains,
/// # 	Overseer,
/// # 	SubsystemError,
/// # 	gen::{
/// # 		SubsystemContext,
/// # 		FromOrchestra,
/// # 		SpawnedSubsystem,
/// # 	},
/// # };
/// # use polkadot_node_subsystem_types::messages::{
/// # 	CandidateValidationMessage, CandidateBackingMessage,
/// # 	NetworkBridgeTxMessage,
/// # };
///
/// struct ValidationSubsystem;
///
/// impl<Ctx> overseer::Subsystem<Ctx, SubsystemError> for ValidationSubsystem
/// where
///     Ctx: overseer::SubsystemContext<
/// 				Message=CandidateValidationMessage,
/// 				AllMessages=AllMessages,
/// 				Signal=OverseerSignal,
/// 				Error=SubsystemError,
/// 			>,
/// {
///     fn start(
///         self,
///         mut ctx: Ctx,
///     ) -> SpawnedSubsystem<SubsystemError> {
///         SpawnedSubsystem {
///             name: "validation-subsystem",
///             future: Box::pin(async move {
///                 loop {
///                     Delay::new(Duration::from_secs(1)).await;
///                 }
///             }),
///         }
///     }
/// }
///
/// # fn main() { executor::block_on(async move {
///
/// struct AlwaysSupportsParachains;
///
/// #[async_trait::async_trait]
/// impl HeadSupportsParachains for AlwaysSupportsParachains {
///      async fn head_supports_parachains(&self, _head: &Hash) -> bool { true }
/// }
///
/// let spawner = sp_core::testing::TaskExecutor::new();
/// let (overseer, _handle) = dummy_overseer_builder(spawner, AlwaysSupportsParachains, None)
/// 		.unwrap()
/// 		.replace_candidate_validation(|_| ValidationSubsystem)
/// 		.build()
/// 		.unwrap();
///
/// let timer = Delay::new(Duration::from_millis(50)).fuse();
///
/// let overseer_fut = overseer.run().fuse();
/// pin_mut!(timer);
/// pin_mut!(overseer_fut);
///
/// select! {
///     _ = overseer_fut => (),
///     _ = timer => (),
/// }
/// #
/// # 	});
/// # }
/// ```
#[orchestra(
	gen=AllMessages,
	event=Event,
	signal=OverseerSignal,
	error=SubsystemError,
	message_capacity=2048,
)]
pub struct Overseer<SupportsParachains> {
	#[subsystem(CandidateValidationMessage, sends: [
		ChainApiMessage,
		RuntimeApiMessage,
	])]
	candidate_validation: CandidateValidation,

	#[subsystem(sends: [
		CandidateValidationMessage,
		RuntimeApiMessage,
	])]
	pvf_checker: PvfChecker,

	#[subsystem(CandidateBackingMessage, sends: [
		CandidateValidationMessage,
		CollatorProtocolMessage,
		ChainApiMessage,
		AvailabilityDistributionMessage,
		AvailabilityStoreMessage,
		StatementDistributionMessage,
		ProvisionerMessage,
		RuntimeApiMessage,
		ProspectiveParachainsMessage,
	])]
	candidate_backing: CandidateBacking,

	#[subsystem(StatementDistributionMessage, sends: [
		NetworkBridgeTxMessage,
		CandidateBackingMessage,
		RuntimeApiMessage,
		ProspectiveParachainsMessage,
		ChainApiMessage,
	], can_receive_priority_messages)]
	statement_distribution: StatementDistribution,

	#[subsystem(AvailabilityDistributionMessage, sends: [
		AvailabilityStoreMessage,
		ChainApiMessage,
		RuntimeApiMessage,
		NetworkBridgeTxMessage,
	])]
	availability_distribution: AvailabilityDistribution,

	#[subsystem(AvailabilityRecoveryMessage, sends: [
		NetworkBridgeTxMessage,
		RuntimeApiMessage,
		AvailabilityStoreMessage,
	])]
	availability_recovery: AvailabilityRecovery,

	#[subsystem(blocking, sends: [
		AvailabilityStoreMessage,
		RuntimeApiMessage,
		BitfieldDistributionMessage,
	])]
	bitfield_signing: BitfieldSigning,

	#[subsystem(blocking, message_capacity: 8192, BitfieldDistributionMessage, sends: [
		RuntimeApiMessage,
		NetworkBridgeTxMessage,
		ProvisionerMessage,
	], can_receive_priority_messages)]
	bitfield_distribution: BitfieldDistribution,

	#[subsystem(ProvisionerMessage, sends: [
		RuntimeApiMessage,
		CandidateBackingMessage,
		DisputeCoordinatorMessage,
		ProspectiveParachainsMessage,
	])]
	provisioner: Provisioner,

	#[subsystem(blocking, RuntimeApiMessage, sends: [])]
	runtime_api: RuntimeApi,

	#[subsystem(blocking, AvailabilityStoreMessage, sends: [
		ChainApiMessage,
		RuntimeApiMessage,
	])]
	availability_store: AvailabilityStore,

	#[subsystem(blocking, NetworkBridgeRxMessage, sends: [
		BitfieldDistributionMessage,
		StatementDistributionMessage,
		ApprovalVotingParallelMessage,
		GossipSupportMessage,
		DisputeDistributionMessage,
		CollationGenerationMessage,
		CollatorProtocolMessage,
	])]
	network_bridge_rx: NetworkBridgeRx,

	#[subsystem(blocking, NetworkBridgeTxMessage, sends: [])]
	network_bridge_tx: NetworkBridgeTx,

	#[subsystem(blocking, ChainApiMessage, sends: [])]
	chain_api: ChainApi,

	#[subsystem(CollationGenerationMessage, sends: [
		RuntimeApiMessage,
		CollatorProtocolMessage,
	])]
	collation_generation: CollationGeneration,

	#[subsystem(CollatorProtocolMessage, sends: [
		NetworkBridgeTxMessage,
		RuntimeApiMessage,
		CandidateBackingMessage,
		ChainApiMessage,
		ProspectiveParachainsMessage,
	])]
	collator_protocol: CollatorProtocol,

	#[subsystem(blocking, message_capacity: 64000, ApprovalDistributionMessage, sends: [
		NetworkBridgeTxMessage,
		ApprovalVotingMessage,
		RuntimeApiMessage,
	], can_receive_priority_messages)]
	approval_distribution: ApprovalDistribution,

	#[subsystem(blocking, ApprovalVotingMessage, sends: [
		ApprovalDistributionMessage,
		AvailabilityRecoveryMessage,
		CandidateValidationMessage,
		ChainApiMessage,
		ChainSelectionMessage,
		DisputeCoordinatorMessage,
		RuntimeApiMessage,
	])]
	approval_voting: ApprovalVoting,
	#[subsystem(blocking, message_capacity: 64000, ApprovalVotingParallelMessage, sends: [
		AvailabilityRecoveryMessage,
		CandidateValidationMessage,
		ChainApiMessage,
		ChainSelectionMessage,
		DisputeCoordinatorMessage,
		RuntimeApiMessage,
		NetworkBridgeTxMessage,
		ApprovalVotingParallelMessage,
	], can_receive_priority_messages)]
	approval_voting_parallel: ApprovalVotingParallel,
	#[subsystem(GossipSupportMessage, sends: [
		NetworkBridgeTxMessage,
		NetworkBridgeRxMessage, // TODO <https://github.com/paritytech/polkadot/issues/5626>
		RuntimeApiMessage,
		ChainSelectionMessage,
		ChainApiMessage,
	], can_receive_priority_messages)]
	gossip_support: GossipSupport,

	#[subsystem(blocking, message_capacity: 32000, DisputeCoordinatorMessage, sends: [
		RuntimeApiMessage,
		ChainApiMessage,
		DisputeDistributionMessage,
		CandidateValidationMessage,
		AvailabilityStoreMessage,
		AvailabilityRecoveryMessage,
		ChainSelectionMessage,
		ApprovalVotingParallelMessage,
	], can_receive_priority_messages)]
	dispute_coordinator: DisputeCoordinator,

	#[subsystem(DisputeDistributionMessage, sends: [
		RuntimeApiMessage,
		DisputeCoordinatorMessage,
		NetworkBridgeTxMessage,
	])]
	dispute_distribution: DisputeDistribution,

	#[subsystem(blocking, ChainSelectionMessage, sends: [ChainApiMessage])]
	chain_selection: ChainSelection,

	#[subsystem(ProspectiveParachainsMessage, sends: [
		RuntimeApiMessage,
		ChainApiMessage,
	])]
	prospective_parachains: ProspectiveParachains,

	/// External listeners waiting for a hash to be in the active-leave set.
	pub activation_external_listeners: HashMap<Hash, Vec<oneshot::Sender<SubsystemResult<()>>>>,

	/// The set of the "active leaves".
	pub active_leaves: HashMap<Hash, BlockNumber>,

	/// An implementation for checking whether a header supports parachain consensus.
	pub supports_parachains: SupportsParachains,

	/// Various Prometheus metrics.
	pub metrics: OverseerMetrics,
}

/// Spawn the metrics metronome task.
pub fn spawn_metronome_metrics<S, SupportsParachains>(
	overseer: &mut Overseer<S, SupportsParachains>,
	metronome_metrics: OverseerMetrics,
) -> Result<(), SubsystemError>
where
	S: Spawner,
	SupportsParachains: HeadSupportsParachains,
{
	struct ExtractNameAndMeters;

	impl<'a, T: 'a> MapSubsystem<&'a OrchestratedSubsystem<T>> for ExtractNameAndMeters {
		type Output = Option<(&'static str, SubsystemMeters)>;

		fn map_subsystem(&self, subsystem: &'a OrchestratedSubsystem<T>) -> Self::Output {
			subsystem
				.instance
				.as_ref()
				.map(|instance| (instance.name, instance.meters.clone()))
		}
	}
	let subsystem_meters = overseer.map_subsystems(ExtractNameAndMeters);

	#[cfg(any(target_os = "linux", feature = "jemalloc-allocator"))]
	let collect_memory_stats: Box<dyn Fn(&OverseerMetrics) + Send> =
		match memory_stats::MemoryAllocationTracker::new() {
			Ok(memory_stats) =>
				Box::new(move |metrics: &OverseerMetrics| match memory_stats.snapshot() {
					Ok(memory_stats_snapshot) => {
						gum::trace!(
							target: LOG_TARGET,
							"memory_stats: {:?}",
							&memory_stats_snapshot
						);
						metrics.memory_stats_snapshot(memory_stats_snapshot);
					},
					Err(e) =>
						gum::debug!(target: LOG_TARGET, "Failed to obtain memory stats: {:?}", e),
				}),
			Err(_) => {
				gum::debug!(
					target: LOG_TARGET,
					"Memory allocation tracking is not supported by the allocator.",
				);

				Box::new(|_| {})
			},
		};

	#[cfg(not(any(target_os = "linux", feature = "jemalloc-allocator")))]
	let collect_memory_stats: Box<dyn Fn(&OverseerMetrics) + Send> = Box::new(|_| {});

	let metronome = Metronome::new(std::time::Duration::from_millis(950)).for_each(move |_| {
		collect_memory_stats(&metronome_metrics);

		// We combine the amount of messages from subsystems to the overseer
		// as well as the amount of messages from external sources to the overseer
		// into one `to_overseer` value.
		metronome_metrics.channel_metrics_snapshot(
			subsystem_meters
				.iter()
				.cloned()
				.flatten()
				.map(|(name, ref meters)| (name, meters.read())),
		);

		futures::future::ready(())
	});
	overseer
		.spawner()
		.spawn("metrics-metronome", Some("overseer"), Box::pin(metronome));

	Ok(())
}

impl<S, SupportsParachains> Overseer<S, SupportsParachains>
where
	SupportsParachains: HeadSupportsParachains,
	S: Spawner,
{
	/// Stop the `Overseer`.
	async fn stop(mut self) {
		let _ = self.wait_terminate(OverseerSignal::Conclude, Duration::from_secs(1_u64)).await;
	}

	/// Run the `Overseer`.
	///
	/// Logging any errors.
	pub async fn run(self) {
		if let Err(err) = self.run_inner().await {
			gum::error!(target: LOG_TARGET, ?err, "Overseer exited with error");
		}
	}

	async fn run_inner(mut self) -> SubsystemResult<()> {
		let metrics = self.metrics.clone();
		spawn_metronome_metrics(&mut self, metrics)?;

		loop {
			select! {
				msg = self.events_rx.select_next_some() => {
					match msg {
						Event::MsgToSubsystem { msg, origin, priority } => {
							match priority {
								PriorityLevel::Normal => {
									self.route_message(msg.into(), origin).await?;
								},
								PriorityLevel::High => {
									self.route_message_with_priority::<HighPriority>(msg.into(), origin).await?;
								},
							}
							self.metrics.on_message_relayed();
						}
						Event::Stop => {
							self.stop().await;
							return Ok(());
						}
						Event::BlockImported(block) => {
							self.block_imported(block).await?;
						}
						Event::BlockFinalized(block) => {
							self.block_finalized(block).await?;
						}
						Event::ExternalRequest(request) => {
							self.handle_external_request(request);
						}
					}
				},
				msg = self.to_orchestra_rx.select_next_some() => {
					match msg {
						ToOrchestra::SpawnJob { name, subsystem, s } => {
							self.spawn_job(name, subsystem, s);
						}
						ToOrchestra::SpawnBlockingJob { name, subsystem, s } => {
							self.spawn_blocking_job(name, subsystem, s);
						}
					}
				},
				res = self.running_subsystems.select_next_some() => {
					gum::error!(
						target: LOG_TARGET,
						subsystem = ?res,
						"subsystem finished unexpectedly",
					);
					self.stop().await;
					return res;
				},
			}
		}
	}

	async fn block_imported(&mut self, block: BlockInfo) -> SubsystemResult<()> {
		match self.active_leaves.entry(block.hash) {
			hash_map::Entry::Vacant(entry) => entry.insert(block.number),
			hash_map::Entry::Occupied(entry) => {
				debug_assert_eq!(*entry.get(), block.number);
				return Ok(())
			},
		};

		let mut update = match self.on_head_activated(&block.hash, Some(block.parent_hash)).await {
			Some(_) => ActiveLeavesUpdate::start_work(ActivatedLeaf {
				hash: block.hash,
				number: block.number,
				unpin_handle: block.unpin_handle,
			}),
			None => ActiveLeavesUpdate::default(),
		};

		if let Some(number) = self.active_leaves.remove(&block.parent_hash) {
			debug_assert_eq!(block.number.saturating_sub(1), number);
			update.deactivated.push(block.parent_hash);
			self.on_head_deactivated(&block.parent_hash);
		}

		self.clean_up_external_listeners();

		if !update.is_empty() {
			self.broadcast_signal(OverseerSignal::ActiveLeaves(update)).await?;
		}
		Ok(())
	}

	async fn block_finalized(&mut self, block: BlockInfo) -> SubsystemResult<()> {
		let mut update = ActiveLeavesUpdate::default();

		self.active_leaves.retain(|h, n| {
			// prune all orphaned leaves, but don't prune
			// the finalized block if it is itself a leaf.
			if *n <= block.number && *h != block.hash {
				update.deactivated.push(*h);
				false
			} else {
				true
			}
		});

		for deactivated in &update.deactivated {
			self.on_head_deactivated(deactivated)
		}

		self.broadcast_signal(OverseerSignal::BlockFinalized(block.hash, block.number))
			.await?;

		// If there are no leaves being deactivated, we don't need to send an update.
		//
		// Our peers will be informed about our finalized block the next time we
		// activating/deactivating some leaf.
		if !update.is_empty() {
			self.broadcast_signal(OverseerSignal::ActiveLeaves(update)).await?;
		}

		Ok(())
	}

	/// Handles a header activation. If the header's state doesn't support the parachains API,
	/// this returns `None`.
	async fn on_head_activated(&mut self, hash: &Hash, _parent_hash: Option<Hash>) -> Option<()> {
		if !self.supports_parachains.head_supports_parachains(hash).await {
			return None
		}

		self.metrics.on_head_activated();
		if let Some(listeners) = self.activation_external_listeners.remove(hash) {
			gum::trace!(
				target: LOG_TARGET,
				relay_parent = ?hash,
				"Leaf got activated, notifying external listeners"
			);
			for listener in listeners {
				// it's fine if the listener is no longer interested
				let _ = listener.send(Ok(()));
			}
		}

		Some(())
	}

	fn on_head_deactivated(&mut self, hash: &Hash) {
		self.metrics.on_head_deactivated();
		self.activation_external_listeners.remove(hash);
	}

	fn clean_up_external_listeners(&mut self) {
		self.activation_external_listeners.retain(|_, v| {
			// remove dead listeners
			v.retain(|c| !c.is_canceled());
			!v.is_empty()
		})
	}

	fn handle_external_request(&mut self, request: ExternalRequest) {
		match request {
			ExternalRequest::WaitForActivation { hash, response_channel } => {
				if self.active_leaves.get(&hash).is_some() {
					gum::trace!(
						target: LOG_TARGET,
						relay_parent = ?hash,
						"Leaf was already ready - answering `WaitForActivation`"
					);
					// it's fine if the listener is no longer interested
					let _ = response_channel.send(Ok(()));
				} else {
					gum::trace!(
						target: LOG_TARGET,
						relay_parent = ?hash,
						"Leaf not yet ready - queuing `WaitForActivation` sender"
					);
					self.activation_external_listeners
						.entry(hash)
						.or_default()
						.push(response_channel);
				}
			},
		}
	}

	fn spawn_job(
		&mut self,
		task_name: &'static str,
		subsystem_name: Option<&'static str>,
		j: BoxFuture<'static, ()>,
	) {
		self.spawner.spawn(task_name, subsystem_name, j);
	}

	fn spawn_blocking_job(
		&mut self,
		task_name: &'static str,
		subsystem_name: Option<&'static str>,
		j: BoxFuture<'static, ()>,
	) {
		self.spawner.spawn_blocking(task_name, subsystem_name, j);
	}
}
