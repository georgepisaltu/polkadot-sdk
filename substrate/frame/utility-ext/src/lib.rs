// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Utility Extension Pallet
//!
//! Batches of calls, each dispatched with its own origin, in the spirit of `pallet_utility`:
//! [`Pallet::batch_multi_origin`] and [`Pallet::force_batch_multi_origin`].
//!
//! ## Overview
//!
//! A multi-origin batch is a regular signed transaction of its submitter whose call carries a list
//! of items. Each item is a general transaction on its own: a call plus an inner
//! [`TransactionExtension`] pipeline ([`Config::InnerExtension`]) which authorizes the item's
//! origin and does its transaction extension bookkeeping (nonce, fee payment, etc.). The call
//! applies the items in sequence: every item runs its pipeline's `validate` and `prepare`, is
//! dispatched and runs its pipeline's `post_dispatch` before the next item starts, exactly as if
//! it were a transaction of its own included right after the previous item.
//!
//! An invalid item (rejected by its pipeline) is not applied at all and its origin pays nothing,
//! like an invalid transaction. An item whose call fails keeps its pipeline's effects (nonce, fee)
//! while the call's effects are reverted, like a failed transaction. Batches are not atomic:
//! `batch_multi_origin` stops at the first item which is invalid or fails and keeps the items
//! before it, `force_batch_multi_origin` applies every item regardless. The outcome is reported
//! in events.
//!
//! The submitter pays for the batch overhead, the items' pipelines and the transaction's length,
//! through the [`MultiOriginBatch`] extension which goes before the runtime's fee payment
//! extension. Items pay for their own calls (the call weight plus the base extrinsic fee, through
//! the fee payment extension of their pipeline). An item whose dispatch returns `Pays::No` costs
//! the submitter nothing either, as it would cost nobody anything as a transaction of its own:
//! its pipeline and bytes are refunded.
//!
//! Items are signed over the [`ItemImplication`] of their batch, which binds them to the
//! submitter, the submitter's nonce, the batch mode, their position and the other items, so an
//! item cannot be applied elsewhere.
//!
//! Items are not validated when the batch enters the transaction pool, only the submitter's
//! transaction is. A batch with invalid items is therefore included and the submitter pays their
//! share for it, including the length of every item, while an item signer can invalidate their
//! item at no cost by using their nonce before the batch is included. Submitters should only
//! batch items of parties they trust to that extent.
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! * `batch_multi_origin` - Dispatch multiple calls, each from its own origin, stopping at the
//!   first failure.
//! * `force_batch_multi_origin` - Dispatch multiple calls, each from its own origin, regardless of
//!   failures.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod benchmarking;
pub mod extension;
mod tests;
pub mod weights;

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
	dispatch::{DispatchClass, DispatchInfo, GetDispatchInfo, Pays, PostDispatchInfo},
	storage::{with_transaction, TransactionOutcome},
	traits::{Contains, IsSubType, OriginTrait},
	BoundedVec,
};
use scale_info::TypeInfo;
use sp_runtime::{
	traits::{
		AsTransactionAuthorizedOrigin, BadOrigin, Dispatchable, ExtensionPostDispatchWeightHandler,
		Hash, TransactionExtension, TxBaseImplication,
	},
	transaction_validity::{InvalidTransaction, TransactionSource, TransactionValidityError},
	DispatchError, Weight,
};
pub mod runtime_api;
pub use weights::WeightInfo;

pub use extension::{ItemImplication, MultiOriginBatch, ITEM_IMPLICATION_PREFIX};
pub use pallet::*;

type RuntimeCallOf<T> = <T as frame_system::Config>::RuntimeCall;
type RuntimeOriginOf<T> = <T as frame_system::Config>::RuntimeOrigin;
type AccountIdOf<T> = <T as frame_system::Config>::AccountId;
type NonceOf<T> = <T as frame_system::Config>::Nonce;
type HashOf<T> = <T as frame_system::Config>::Hash;
type PalletsOriginOf<T> = <RuntimeOriginOf<T> as OriginTrait>::PalletsOrigin;
type InnerExtensionOf<T> = <T as Config>::InnerExtension;

/// How a multi-origin batch handles an item which is invalid or whose call fails.
#[derive(
	Encode,
	Decode,
	DecodeWithMemTracking,
	Clone,
	Copy,
	PartialEq,
	Eq,
	Debug,
	TypeInfo,
	MaxEncodedLen,
)]
pub enum BatchMode {
	/// Stop at the first such item and keep the items before it
	/// ([`Pallet::batch_multi_origin`]).
	Stop,
	/// Apply every item regardless ([`Pallet::force_batch_multi_origin`]).
	Continue,
}

/// Why an item of a multi-origin batch was not applied successfully.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub enum ItemError {
	/// The item's inner pipeline rejected it. Nothing of the item was applied and its origin paid
	/// nothing, like an invalid transaction.
	Invalid(TransactionValidityError),
	/// The item's call failed. The item's pipeline was applied (nonce, fee payment, etc.) and the
	/// call's effects were reverted, like a failed transaction.
	Failed(DispatchError),
}

/// An extension of the item pipeline with its data, as wallets see it. See
/// [`Pallet::item_extensions`].
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct ItemExtension {
	/// The extension's identifier, as in the metadata.
	pub identifier: alloc::string::String,
	/// The extension's encoded explicit data.
	pub explicit: Vec<u8>,
	/// The extension's encoded implicit data.
	pub implicit: Vec<u8>,
}

/// Why an item could not be applied: whether its call was dispatched or not.
enum RunError {
	/// The item's pipeline rejected it in `validate` or `prepare`. Nothing was dispatched.
	BeforeDispatch(TransactionValidityError),
	/// The item's pipeline failed in `post_dispatch`, after the call ran.
	AfterDispatch(TransactionValidityError),
}

/// An item of a multi-origin batch.
///
/// A general transaction without preamble: a call plus the inner extension pipeline which
/// authorizes it, validated with the [`ItemImplication`] of its batch.
#[derive(Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, TypeInfo, Clone, Debug)]
pub struct MultiOriginItem<Call, Extension, Origin> {
	/// The call to dispatch with the origin authorized by `extension`.
	pub call: Call,
	/// The inner transaction extension pipeline of this item.
	pub extension: Extension,
	/// The origin `extension` must authorize.
	///
	/// Every item signs over the calls and origins of all items (see [`ItemImplication`]), so
	/// stating the origin here binds the signers to their counterparties.
	pub origin: Origin,
}

impl<Call, Extension, Origin> MultiOriginItem<Call, Extension, Origin> {
	/// Create a new multi-origin batch item.
	pub fn new(call: Call, extension: Extension, origin: Origin) -> Self {
		Self { call, extension, origin }
	}
}

/// The [`MultiOriginItem`] for the given config.
pub type MultiOriginItemOf<T> =
	MultiOriginItem<RuntimeCallOf<T>, <T as Config>::InnerExtension, PalletsOriginOf<T>>;

/// The items of a multi-origin batch for the given config.
pub type MultiOriginItemsOf<T> =
	BoundedVec<MultiOriginItemOf<T>, <T as Config>::MaxMultiOriginBatch>;

/// The origin of the multi-origin batch calls.
#[derive(
	PartialEq, Eq, Clone, Encode, Decode, DecodeWithMemTracking, Debug, TypeInfo, MaxEncodedLen,
)]
pub enum RawOrigin<AccountId, Nonce> {
	/// A multi-origin batch authorized by the [`MultiOriginBatch`] transaction extension,
	/// submitted by `submitter` as their transaction with `nonce`.
	MultiOriginBatch {
		/// The account which signed and paid for the batch transaction.
		submitter: AccountId,
		/// The nonce of the batch transaction.
		nonce: Nonce,
	},
}

/// Builds the items the benchmarks dispatch.
///
/// The items run the real [`Config::InnerExtension`] pipeline, so the benchmarked overhead of a
/// batch call includes one pipeline run and one call per item on top of what the items declare
/// and are charged for themselves. The resulting overestimate is paid only by batch submitters;
/// see the `benchmarking` module docs.
#[cfg(feature = "runtime-benchmarks")]
pub trait BenchmarkHelper<T: Config> {
	/// Set up the origin the benchmark items are authorized with and return it. The origin must
	/// be able to pay for `MaxMultiOriginBatch` `frame_system::remark` calls.
	fn setup() -> PalletsOriginOf<T>;

	/// An item dispatching `call` with that origin, with `nonce` as its nonce, authorized over
	/// `implication`, the encoded [`ItemImplication`] of the item.
	fn item(
		call: RuntimeCallOf<T>,
		nonce: NonceOf<T>,
		implication: Vec<u8>,
	) -> MultiOriginItemOf<T>;
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// Configuration trait.
	#[pallet::config]
	pub trait Config:
		frame_system::Config<
		RuntimeCall: Dispatchable<
			Info = DispatchInfo,
			PostInfo = PostDispatchInfo,
			RuntimeOrigin = <Self as frame_system::Config>::RuntimeOrigin,
		> + IsSubType<Call<Self>>
		                 + From<Call<Self>>,
		RuntimeOrigin: From<Origin<Self>>
		                   + Into<Result<Origin<Self>, <Self as frame_system::Config>::RuntimeOrigin>>,
	>
	{
		/// The transaction extension pipeline carried by every item of a multi-origin batch.
		///
		/// It authorizes the item's origin and does the item's own bookkeeping (nonce, fee payment,
		/// etc.). It should be configured as a subset of the runtime's pipeline, but it must not
		/// include extensions which act on the transaction as a whole, such as `CheckWeight` or
		/// `WeightReclaim`, and must not include [`MultiOriginBatch`] itself.
		///
		/// The [`ItemImplication`] items are signed over binds them to their batch but not to the
		/// chain, so the pipeline must include the extensions binding a signature to the chain,
		/// such as `CheckGenesis`, `CheckSpecVersion` and `CheckTxVersion`, and it should include
		/// `CheckEra` so that items expire. The extension verifying signatures must come before
		/// `AuthorizeCall`, or a signed item dispatching an authorized call is never valid. Items
		/// are validated with [`TransactionSource::External`], as they come from outside, and the
		/// validity their pipeline returns is not used: neither the `provides` tags of authorized
		/// calls, which therefore do not deduplicate items, so such calls must check their state
		/// in `authorize`, nor `requires` tags.
		///
		/// Items are applied with an extension weight of zero and a length of zero, since the
		/// submitter of the batch pays for the pipelines and the transaction's length. The
		/// pipeline is responsible for charging the item's origin for the item's call: a fee
		/// payment extension in it charges the call weight plus the base extrinsic fee. Stock fee
		/// payment extensions charge `Signed` origins only, so the fee payment extension must come
		/// after the extension which authorizes the paying origin, and it should come before any
		/// extension which refunds weight for that origin in `post_dispatch`, as such a refund
		/// lowers what a fee payment extension placed after it charges. An extension authorizing
		/// another kind of origin must bring its own spam protection for the calls it authorizes.
		/// The pipeline's `post_dispatch` must not fail: an item whose `post_dispatch` fails is
		/// rolled back after its call ran, and nobody pays for the call although the block
		/// accounts for it.
		///
		/// The type is part of the pallet's metadata, so that wallets can build items. The
		/// [`runtime_api::MultiOriginBatchApi`] gives them the pipeline's implicit data and the
		/// payload an item's origin authorizes.
		type InnerExtension: TransactionExtension<RuntimeCallOf<Self>> + TypeInfo;

		/// Builds the items the benchmarks dispatch.
		#[cfg(feature = "runtime-benchmarks")]
		type BenchmarkHelper: BenchmarkHelper<Self>;

		/// The maximum number of items in a multi-origin batch.
		///
		/// As a guideline for runtime devs, this should not be greater than 8.
		#[pallet::constant]
		type MaxMultiOriginBatch: Get<u32>;

		/// The calls an item of a multi-origin batch may dispatch, directly or nested in other
		/// calls.
		///
		/// The filter is enforced as follows:
		/// - The item's call is checked against it when the batch transaction is validated.
		/// - Calls nested in it are checked at dispatch, through a filter attached to the item's
		///   origin.
		/// - That origin filter is lost when a call dispatches its inner call with a fresh origin,
		///   e.g. `pallet_proxy::proxy` or `pallet_sudo::sudo_as`. Calls nested that way are not
		///   filtered.
		type MultiOriginCallFilter: Contains<RuntimeCallOf<Self>>;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	/// The origin of the multi-origin batch calls.
	#[pallet::origin]
	pub type Origin<T> = RawOrigin<AccountIdOf<T>, NonceOf<T>>;

	/// The part of the submitter's share which the items made refundable: the pipeline weight and
	/// the encoded length of the items whose dispatch returned `Pays::No`, which as transactions
	/// of their own would have cost nobody anything.
	///
	/// The batch calls set it at dispatch and [`MultiOriginBatch`] consumes it in `post_dispatch`
	/// to settle the submitter's fee, after clearing it in `prepare` so that only what the
	/// dispatch wrote is read. It never outlives a batch transaction, so its operations are not
	/// benchmarked.
	#[pallet::storage]
	#[pallet::whitelist_storage]
	pub type RefundableShare<T: Config> = StorageValue<_, (Weight, u32), OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event {
		/// The item at `index` of a multi-origin batch was applied successfully.
		ItemCompleted { index: u32 },
		/// The item at `index` of a `force_batch_multi_origin` call was invalid or its call
		/// failed. The batch went on with the next item.
		ItemFailed { index: u32, error: ItemError },
		/// A `batch_multi_origin` call stopped at the item at `index`, which was invalid or whose
		/// call failed. The items before it stay applied.
		BatchInterrupted { index: u32, error: ItemError },
		/// Every item of a multi-origin batch was applied successfully.
		BatchCompleted,
		/// Every item of a `force_batch_multi_origin` call was applied, some unsuccessfully.
		BatchCompletedWithErrors,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Dispatch a batch of calls, each with its own origin, stopping at the first failure.
		///
		/// Each item is a general transaction on its own: a call plus an inner transaction
		/// extension pipeline ([`Config::InnerExtension`]) which authorizes the item's origin and
		/// does its bookkeeping (nonce, fee payment, etc.). Items are applied in sequence, each
		/// one validated, prepared, dispatched and post dispatched before the next one starts.
		///
		/// The dispatch origin for this call must be [`RawOrigin::MultiOriginBatch`], which the
		/// [`MultiOriginBatch`] transaction extension provides: the batch must be submitted as a
		/// signed transaction whose signer pays the submitter's share, see the pallet docs.
		///
		/// Like `pallet_utility::batch`, the call stops at the first item which is invalid or
		/// whose call fails, keeps the items applied before it and succeeds. The outcome is
		/// reported in events.
		///
		/// Items cannot nest multi-origin batch calls, can only dispatch calls allowed by
		/// [`Config::MultiOriginCallFilter`] and must be of dispatch class `Normal`. The batch
		/// must not be empty.
		#[pallet::call_index(0)]
		#[pallet::weight({
			let weight = Pallet::<T>::submitter_weight(items, BatchMode::Stop)
				.saturating_add(Pallet::<T>::items_call_weight(items));
			(weight, DispatchClass::Normal)
		})]
		pub fn batch_multi_origin(
			origin: OriginFor<T>,
			items: MultiOriginItemsOf<T>,
		) -> DispatchResultWithPostInfo {
			Self::do_batch(origin, items, BatchMode::Stop)
		}

		/// Dispatch a batch of calls, each with its own origin, regardless of failures.
		///
		/// Like [`Pallet::batch_multi_origin`], but like `pallet_utility::force_batch` it goes on
		/// with the next item when an item is invalid or its call fails.
		#[pallet::call_index(1)]
		#[pallet::weight({
			let weight = Pallet::<T>::submitter_weight(items, BatchMode::Continue)
				.saturating_add(Pallet::<T>::items_call_weight(items));
			(weight, DispatchClass::Normal)
		})]
		pub fn force_batch_multi_origin(
			origin: OriginFor<T>,
			items: MultiOriginItemsOf<T>,
		) -> DispatchResultWithPostInfo {
			Self::do_batch(origin, items, BatchMode::Continue)
		}
	}

	impl<T: Config> Pallet<T> {
		/// Ensure `origin` is [`RawOrigin::MultiOriginBatch`] and return the submitter and nonce.
		pub fn ensure_multi_origin_batch(
			origin: OriginFor<T>,
		) -> Result<(AccountIdOf<T>, NonceOf<T>), BadOrigin> {
			let origin: Result<Origin<T>, OriginFor<T>> = origin.into();
			match origin {
				Ok(RawOrigin::MultiOriginBatch { submitter, nonce }) => Ok((submitter, nonce)),
				_ => Err(BadOrigin),
			}
		}

		/// The items and mode of `call` if it is a multi-origin batch call.
		pub fn batch_items(call: &RuntimeCallOf<T>) -> Option<(&MultiOriginItemsOf<T>, BatchMode)> {
			match call.is_sub_type() {
				Some(Call::batch_multi_origin { items }) => Some((items, BatchMode::Stop)),
				Some(Call::force_batch_multi_origin { items }) => {
					Some((items, BatchMode::Continue))
				},
				_ => None,
			}
		}

		/// Whether `call` may be dispatched by an item, directly or nested.
		pub fn item_call_allowed(call: &RuntimeCallOf<T>) -> bool {
			<T as Config>::MultiOriginCallFilter::contains(call) &&
				Self::batch_items(call).is_none()
		}

		/// Check everything about `items` which can be checked before anything runs: the batch
		/// is not empty and every item's call is allowed and of dispatch class `Normal`.
		pub fn check_items(items: &MultiOriginItemsOf<T>) -> Result<(), TransactionValidityError> {
			if items.is_empty() {
				return Err(InvalidTransaction::Call.into());
			}
			for item in items.iter() {
				if !Self::item_call_allowed(&item.call) ||
					item.call.get_dispatch_info().class != DispatchClass::Normal
				{
					return Err(InvalidTransaction::Call.into());
				}
			}
			Ok(())
		}

		/// The hash committing to the calls and origins of `items`, in order, which every item is
		/// signed over: the hash of the SCALE encoding of the list of `(call, origin)` pairs.
		pub fn items_hash<'a>(
			items: impl IntoIterator<Item = (&'a RuntimeCallOf<T>, &'a PalletsOriginOf<T>)>,
		) -> HashOf<T> {
			let commitments: Vec<_> = items.into_iter().collect();
			<T as frame_system::Config>::Hashing::hash_of(&commitments)
		}

		/// The extensions of the item pipeline `extension`, in metadata order, each with its
		/// encoded explicit and implicit data. `None` if the implicit data is unavailable.
		///
		/// The payload which the extension at some position sees in `validate`, and which an
		/// authorizing extension there signs or hashes, is the item's [`ItemImplication`]
		/// followed by the explicit then the implicit data of the extensions after it; see
		/// [`Self::item_signing_payload`].
		pub fn item_extensions(extension: &InnerExtensionOf<T>) -> Option<Vec<ItemExtension>> {
			let identifiers = InnerExtensionOf::<T>::metadata();
			let explicit = extension.explicit_parts();
			let implicit = extension.implicit_parts().ok()?;
			if identifiers.len() != explicit.len() || explicit.len() != implicit.len() {
				return None;
			}
			let extensions = identifiers
				.into_iter()
				.zip(explicit)
				.zip(implicit)
				.map(|((metadata, explicit), implicit)| ItemExtension {
					identifier: metadata.identifier.into(),
					explicit,
					implicit,
				})
				.collect();
			Some(extensions)
		}

		/// The payload the origin of the item at `index` of a batch authorizes, as its pipeline
		/// `extension` hands it to the authorizing extension at `authorizer`, the position of
		/// that extension in metadata order: the item's [`ItemImplication`] followed by the
		/// explicit then the implicit data of the extensions after it. The batch is described by
		/// its `mode`, its `submitter` with the `nonce` of the batch transaction and the calls
		/// and origins of all its `items`, in order.
		///
		/// `None` if `authorizer` is out of range or the implicit data is unavailable.
		pub fn item_signing_payload<'a>(
			mode: BatchMode,
			submitter: &AccountIdOf<T>,
			nonce: NonceOf<T>,
			index: u32,
			items: impl IntoIterator<Item = (&'a RuntimeCallOf<T>, &'a PalletsOriginOf<T>)>,
			extension: &InnerExtensionOf<T>,
			authorizer: u32,
		) -> Option<Vec<u8>> {
			let items_hash = Self::items_hash(items);
			let implication =
				ItemImplication { mode, submitter, nonce, index, items_hash: &items_hash };
			let explicit = extension.explicit_parts();
			let implicit = extension.implicit_parts().ok()?;
			let following = (authorizer as usize).checked_add(1)?;
			if following > explicit.len() || following > implicit.len() {
				return None;
			}
			let mut payload = implication.encode();
			explicit[following..].iter().for_each(|part| payload.extend_from_slice(part));
			implicit[following..].iter().for_each(|part| payload.extend_from_slice(part));
			Some(payload)
		}

		/// The weight of the pallet's own work for a batch of `count` items in `mode`.
		pub fn overhead_weight(mode: BatchMode, count: u32) -> Weight {
			match mode {
				BatchMode::Stop => <T as Config>::WeightInfo::batch_multi_origin(count),
				BatchMode::Continue => <T as Config>::WeightInfo::force_batch_multi_origin(count),
			}
		}

		/// The weight of the inner pipelines of `items`.
		pub fn items_extension_weight(items: &MultiOriginItemsOf<T>) -> Weight {
			items.iter().fold(Weight::zero(), |weight, item| {
				weight.saturating_add(item.extension.weight(&item.call))
			})
		}

		/// The weight of the calls of `items`.
		pub fn items_call_weight(items: &MultiOriginItemsOf<T>) -> Weight {
			items.iter().fold(Weight::zero(), |weight, item| {
				weight.saturating_add(item.call.get_dispatch_info().call_weight)
			})
		}

		/// The part of a batch's weight its submitter pays for: the pallet's own work and the
		/// items' pipelines. The items pay for their calls.
		pub fn submitter_weight(items: &MultiOriginItemsOf<T>, mode: BatchMode) -> Weight {
			Self::overhead_weight(mode, items.len() as u32)
				.saturating_add(Self::items_extension_weight(items))
		}

		fn do_batch(
			origin: OriginFor<T>,
			items: MultiOriginItemsOf<T>,
			mode: BatchMode,
		) -> DispatchResultWithPostInfo {
			let (submitter, nonce) = Self::ensure_multi_origin_batch(origin)?;
			let count = items.len() as u32;
			let items_hash = Self::items_hash(items.iter().map(|item| (&item.call, &item.origin)));

			let mut weight = Weight::zero();
			let mut refundable = (Weight::zero(), 0u32);
			let mut has_error = false;
			for (index, item) in items.into_iter().enumerate() {
				let index = index as u32;
				let implication = ItemImplication {
					mode,
					submitter: &submitter,
					nonce,
					index,
					items_hash: &items_hash,
				};
				let extension_weight = item.extension.weight(&item.call);
				let len = item.encoded_size() as u32;
				let (item_weight, pays, outcome) =
					Self::apply_item(item, extension_weight, &implication);
				weight = weight.saturating_add(item_weight);
				if pays == Pays::No {
					// Free as a transaction of its own, so free for the submitter too.
					refundable.0 = refundable.0.saturating_add(extension_weight);
					refundable.1 = refundable.1.saturating_add(len);
				}
				match outcome {
					Ok(()) => Self::deposit_event(Event::ItemCompleted { index }),
					Err(error) => match mode {
						BatchMode::Stop => {
							Self::deposit_event(Event::BatchInterrupted { index, error });
							RefundableShare::<T>::put(refundable);
							let overhead = Self::overhead_weight(mode, index.saturating_add(1));
							return Ok(Some(overhead.saturating_add(weight)).into());
						},
						BatchMode::Continue => {
							has_error = true;
							Self::deposit_event(Event::ItemFailed { index, error });
						},
					},
				}
			}
			Self::deposit_event(if has_error {
				Event::BatchCompletedWithErrors
			} else {
				Event::BatchCompleted
			});
			RefundableShare::<T>::put(refundable);
			let overhead = Self::overhead_weight(mode, count);
			Ok(Some(overhead.saturating_add(weight)).into())
		}

		/// Apply an item of a batch, in a storage transaction which is rolled back if the item is
		/// invalid and committed otherwise, like a block builder does with a transaction. Returns
		/// the weight the item used, whether its dispatch pays a fee and its outcome.
		fn apply_item(
			item: MultiOriginItemOf<T>,
			extension_weight: Weight,
			implication: &ItemImplication<AccountIdOf<T>, NonceOf<T>, HashOf<T>>,
		) -> (Weight, Pays, Result<(), ItemError>) {
			// The submitter paid for the pipeline, so the item is applied with an extension
			// weight of zero and pays for its call only. The pipeline's weight is accounted at its
			// worst case: what its extensions refund in `post_dispatch` is ignored.
			let mut info = item.call.get_dispatch_info();
			info.extension_weight = Weight::zero();
			let call_weight = info.call_weight;

			let result = with_transaction::<_, DispatchError, _>(|| {
				match Self::run_item(item, implication, &info) {
					// Validity errors roll back everything the pipeline did, including fee
					// withdrawals. Nothing was dispatched.
					Err(err) => TransactionOutcome::Rollback(Ok(Err(err))),
					// A failed call already had its own effects reverted by its storage layer
					// while its pipeline's effects, the fee included, are kept.
					Ok(res) => TransactionOutcome::Commit(Ok(Ok(res))),
				}
			})
			.unwrap_or_else(|_| {
				Err(RunError::BeforeDispatch(InvalidTransaction::ExhaustsResources.into()))
			});

			match result {
				Err(RunError::BeforeDispatch(err)) => {
					(extension_weight, Pays::Yes, Err(ItemError::Invalid(err)))
				},
				// The call ran and was rolled back with the rest of the item, so nobody paid for
				// it: it is booked at its worst case so that the block accounts for it.
				Err(RunError::AfterDispatch(err)) => (
					extension_weight.saturating_add(call_weight),
					Pays::Yes,
					Err(ItemError::Invalid(err)),
				),
				Ok((call_weight, pays, result)) => (
					extension_weight.saturating_add(call_weight),
					pays,
					result.map_err(ItemError::Failed),
				),
			}
		}

		/// Run an item as a general transaction bound to its batch: validate and prepare its
		/// pipeline, dispatch its call and post dispatch its pipeline. Returns the actual weight
		/// of the call, whether it pays a fee and its result.
		fn run_item(
			item: MultiOriginItemOf<T>,
			implication: &ItemImplication<AccountIdOf<T>, NonceOf<T>, HashOf<T>>,
			info: &DispatchInfo,
		) -> Result<(Weight, Pays, Result<(), DispatchError>), RunError> {
			let MultiOriginItem { call, extension, origin: expected } = item;
			let implication = TxBaseImplication(implication);
			let (_, val, origin) = extension
				.validate(
					frame_system::RawOrigin::None.into(),
					&call,
					info,
					0,
					extension.implicit().map_err(RunError::BeforeDispatch)?,
					&implication,
					TransactionSource::External,
				)
				.map_err(RunError::BeforeDispatch)?;
			if !origin.is_transaction_authorized() {
				return Err(RunError::BeforeDispatch(InvalidTransaction::UnknownOrigin.into()));
			}
			if origin.caller() != &expected {
				return Err(RunError::BeforeDispatch(InvalidTransaction::BadSigner.into()));
			}
			let pre = extension
				.prepare(val, &origin, &call, info, 0)
				.map_err(RunError::BeforeDispatch)?;

			// Don't allow items to nest multi-origin batch calls nor to dispatch calls the
			// runtime keeps out of multi-origin batches.
			let mut origin: RuntimeOriginOf<T> = origin;
			origin.add_filter(Self::item_call_allowed);
			let mut res = call.dispatch(origin);
			let pd_res = res.map(|_| ()).map_err(|e| e.error);
			let post_info = match &mut res {
				Ok(info) => info,
				Err(err) => &mut err.post_info,
			};
			post_info.set_extension_weight(info);
			// Taken before the pipeline's `post_dispatch`, which may refund extension weight into
			// it; that weight is accounted at its worst case by the caller.
			let call_weight = post_info.calc_actual_weight(info);
			let pays = post_info.pays_fee(info);
			InnerExtensionOf::<T>::post_dispatch(pre, info, post_info, 0, &pd_res)
				.map_err(RunError::AfterDispatch)?;
			Ok((call_weight, pays, pd_res))
		}
	}
}
