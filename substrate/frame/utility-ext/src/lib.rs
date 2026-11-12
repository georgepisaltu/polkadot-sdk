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
//! A multi-origin batch is a regular signed transaction of its submitter whose call carries the
//! submitter's nonce and a list of items. Each item is a general transaction on its own: a call
//! plus an inner [`TransactionExtension`] pipeline ([`Config::InnerExtension`]) which authorizes
//! the item's origin and does its transaction extension bookkeeping (nonce, mortality, etc.). The
//! call applies the items in sequence: every item runs its pipeline's `validate` and `prepare`, is
//! dispatched and runs its pipeline's `post_dispatch` before the next item starts, as if it were a
//! transaction of its own included right after the previous item. Items cannot nest multi-origin
//! batch calls and can only dispatch calls allowed by [`Config::MultiOriginCallFilter`]: such
//! items are invalid, and nested calls are filtered at dispatch.
//!
//! An invalid item (rejected by its pipeline) is not applied at all, like an invalid transaction.
//! An item whose call fails keeps its pipeline's effects (nonce) while the call's effects are
//! reverted, like a failed transaction. An item whose pipeline fails in `post_dispatch` is rolled
//! back after its call ran and the submitter pays for its declared weight. Batches are not atomic:
//! `batch_multi_origin` stops at the first item which is invalid or fails and keeps the items
//! before it, `force_batch_multi_origin` applies every item regardless. The outcome is reported
//! in events.
//!
//! The submitter pays for the whole batch like for any transaction: the overhead, the items'
//! pipelines and calls and the transaction's length, through the runtime's fee payment extension,
//! wrapped in [`RefundFreeItems`] so that it refunds the share of the items whose dispatch returned
//! `Pays::No`, their weight and their bytes, as such calls cost nobody anything as transactions of
//! their own. Only `Pays::No` counts: a call feeless through `pallet_skip_feeless_payment` is paid
//! for as an item. Items pay nothing and their pipelines must not charge fees.
//!
//! Items are signed over the [`ItemImplication`] of their batch, which binds them to the
//! submitter, the submitter's nonce, the batch mode, their position and the other items, so an
//! item cannot be applied elsewhere. The call checks that `nonce + 1` is the submitter's current
//! nonce, i.e. that `nonce` is the one `CheckNonce` just bumped, so the runtime's pipeline must
//! contain `CheckNonce`. Like any transaction pipeline, the item pipeline must bring its own
//! replay protection, e.g. `CheckNonce`.
//!
//! Items are not validated when the batch enters the transaction pool, only the submitter's
//! transaction is. A batch with invalid items is therefore included and the submitter pays for
//! it, the invalid items' pipelines and bytes included, while an item signer can invalidate their
//! item at no cost by using their nonce before the batch is included. Submitters should only
//! batch items of parties they trust to that extent.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod benchmarking;
pub mod extension;
mod tests;
pub mod weights;

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
	dispatch::{
		DispatchClass, DispatchInfo, GetDispatchInfo, Pays, PostDispatchInfo, WithPostDispatchInfo,
	},
	storage::{transactional::with_transaction_opaque_err, TransactionOutcome},
	traits::{Contains, IsSubType, OriginTrait},
	BoundedVec,
};
use scale_info::TypeInfo;
use sp_runtime::{
	traits::{
		AsTransactionAuthorizedOrigin, CheckedAdd, Dispatchable,
		ExtensionPostDispatchWeightHandler, Hash, One, TransactionExtension, TxBaseImplication,
	},
	transaction_validity::{InvalidTransaction, TransactionSource, TransactionValidityError},
	DispatchError, Weight,
};
pub use weights::WeightInfo;

pub use extension::RefundFreeItems;
pub use pallet::*;

type RuntimeCallOf<T> = <T as frame_system::Config>::RuntimeCall;
type RuntimeOriginOf<T> = <T as frame_system::Config>::RuntimeOrigin;
type AccountIdOf<T> = <T as frame_system::Config>::AccountId;
type NonceOf<T> = <T as frame_system::Config>::Nonce;
type HashOf<T> = <T as frame_system::Config>::Hash;
type PalletsOriginOf<T> = <RuntimeOriginOf<T> as OriginTrait>::PalletsOrigin;

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
	/// [`Pallet::batch_multi_origin`].
	StopAtFailure,
	/// [`Pallet::force_batch_multi_origin`].
	All,
}

/// Why an item of a multi-origin batch was not applied successfully.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub enum ItemError {
	/// The item's pipeline rejected it.
	Invalid(TransactionValidityError),
	/// The item's call failed.
	Failed(DispatchError),
}

/// Why an item could not be applied.
enum RunError {
	/// It was rejected before dispatch.
	BeforeDispatch(TransactionValidityError),
	/// Its pipeline failed in `post_dispatch`, after the call ran.
	AfterDispatch(TransactionValidityError),
}

/// An item of a multi-origin batch: a general transaction without preamble, validated with the
/// [`ItemImplication`] of its batch.
#[derive(Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, TypeInfo, Clone, Debug)]
pub struct MultiOriginItem<Call, Extension, Origin> {
	/// The call to dispatch.
	pub call: Call,
	/// The pipeline authorizing `origin`.
	pub extension: Extension,
	/// The origin `extension` must authorize.
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

/// Leads the encoding of [`ItemImplication`], so that it does not encode like the implication of
/// a regular transaction, `(extension_version, call)`, for any realistic extension version and
/// pallet index.
pub const ITEM_IMPLICATION_PREFIX: &[u8; 8] = b"_mbatch_";

/// The base implication of an item, in place of the usual `(extension_version, call)`, binding
/// it to its batch. Encodes as [`ITEM_IMPLICATION_PREFIX`] followed by its fields in order.
///
/// The authorizing extension at the head of the item pipeline sees it in `validate` followed by
/// the explicit, then the implicit data of the extensions after it: `VerifySignature` hashes and
/// verifies that whole payload.
pub struct ItemImplication<'a, AccountId, Nonce, Hash> {
	/// The mode of the batch.
	pub mode: BatchMode,
	/// The account submitting the batch.
	pub submitter: &'a AccountId,
	/// The nonce of the submitter's batch transaction.
	pub nonce: Nonce,
	/// The position of the item in the batch.
	pub index: u32,
	/// [`Pallet::items_hash`](crate::Pallet::items_hash) of the batch.
	pub items_hash: &'a Hash,
}

impl<'a, AccountId: Encode, Nonce: Encode, Hash: Encode> Encode
	for ItemImplication<'a, AccountId, Nonce, Hash>
{
	fn encode_to<O: codec::Output + ?Sized>(&self, dest: &mut O) {
		dest.write(ITEM_IMPLICATION_PREFIX);
		self.mode.encode_to(dest);
		self.submitter.encode_to(dest);
		self.nonce.encode_to(dest);
		self.index.encode_to(dest);
		self.items_hash.encode_to(dest);
	}
}

/// Builds the items the benchmarks dispatch, see the [`benchmarking`] module docs.
#[cfg(feature = "runtime-benchmarks")]
pub trait BenchmarkHelper<T: Config> {
	/// Set up an origin whose item pipeline accepts up to `MaxMultiOriginBatch`
	/// `frame_system::remark` items of any length with the nonces 0, 1, ..., and return it.
	fn setup() -> PalletsOriginOf<T>;

	/// An item of that origin dispatching `call` with `nonce`, authorized over `implication`, the
	/// encoded [`ItemImplication`] of the item.
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
		> + IsSubType<Call<Self>>,
	>
	{
		/// The transaction extension pipeline carried by every item of a multi-origin batch.
		///
		/// A subset of the runtime's pipeline without the extensions acting on the transaction as a
		/// whole (`CheckWeight`, `WeightReclaim`) and without the fee payment extension, whose
		/// `post_dispatch` would take the transient credit of `pallet_transaction_payment`, where
		/// the submitter's fee waits, and refund it to the item's signer. As the
		/// [`ItemImplication`] binds items to their batch but not to the chain, it is recommended
		/// to include `CheckGenesis`, `CheckSpecVersion`, `CheckTxVersion` and `CheckEra`. The
		/// extension verifying signatures should come first, so that the data of every other
		/// extension is in the implication it signs.
		///
		/// Items are validated with [`TransactionSource::External`]. The validity their pipeline
		/// returns is dropped: `provides` tags do not deduplicate items, so authorized calls must
		/// check their state in `authorize`.
		///
		/// The inner extension is part of the pallet's metadata, which, with the
		/// [`ItemImplication`] encoding, is what wallets need to build items.
		type InnerExtension: TransactionExtension<RuntimeCallOf<Self>> + TypeInfo;

		/// Builds the items the benchmarks dispatch.
		#[cfg(feature = "runtime-benchmarks")]
		type BenchmarkHelper: BenchmarkHelper<Self>;

		/// The maximum number of items in a multi-origin batch.
		#[pallet::constant]
		type MaxMultiOriginBatch: Get<u32>;

		/// The calls an item of a multi-origin batch may dispatch, directly or nested.
		///
		/// Calls dispatched with a fresh origin, e.g. by `pallet_proxy::proxy` or
		/// `pallet_sudo::sudo_as`, escape the filter put on the item's origin for nested calls.
		/// Calls relying on the transient fee credit of `pallet_transaction_payment` belonging to
		/// the transaction's signer must be kept out.
		type MultiOriginCallFilter: Contains<RuntimeCallOf<Self>>;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	/// The weight and encoded length of the items of the last batch whose dispatch returned
	/// `Pays::No`, consumed by [`RefundFreeItems`] in `post_dispatch` when the batch is the
	/// transaction's call. A batch dispatched any other way leaves it behind until the next batch
	/// transaction clears it in `prepare`. Whitelisted, so its operations are not benchmarked.
	#[pallet::storage]
	#[pallet::whitelist_storage]
	pub type RefundableShare<T: Config> = StorageValue<_, (Weight, u32), OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event {
		/// The item at `index` was applied successfully.
		ItemCompleted { index: u32 },
		/// The item at `index` of a `force_batch_multi_origin` call was not applied successfully.
		ItemFailed { index: u32, error: ItemError },
		/// A `batch_multi_origin` call stopped at the item at `index`.
		BatchInterrupted { index: u32, error: ItemError },
		/// Every item was applied successfully.
		BatchCompleted,
		/// Every item of a `force_batch_multi_origin` call was applied, some unsuccessfully.
		BatchCompletedWithErrors,
	}

	#[pallet::error]
	pub enum Error<T> {
		/// `nonce + 1` is not the submitter's nonce.
		BadNonce,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Dispatch `items`, stopping at the first which is invalid or fails, like
		/// `pallet_utility::batch`. See the crate docs.
		#[pallet::call_index(0)]
		#[pallet::weight((Pallet::<T>::batch_weight(items), DispatchClass::Normal))]
		pub fn batch_multi_origin(
			origin: OriginFor<T>,
			items: MultiOriginItemsOf<T>,
			nonce: NonceOf<T>,
		) -> DispatchResultWithPostInfo {
			Self::do_batch(origin, items, nonce, BatchMode::StopAtFailure)
		}

		/// Like [`Pallet::batch_multi_origin`], but going on with the next item when an item is
		/// invalid or its call fails, like `pallet_utility::force_batch`.
		#[pallet::call_index(1)]
		#[pallet::weight((Pallet::<T>::batch_weight(items), DispatchClass::Normal))]
		pub fn force_batch_multi_origin(
			origin: OriginFor<T>,
			items: MultiOriginItemsOf<T>,
			nonce: NonceOf<T>,
		) -> DispatchResultWithPostInfo {
			Self::do_batch(origin, items, nonce, BatchMode::All)
		}
	}

	impl<T: Config> Pallet<T> {
		/// Whether `call` is a multi-origin batch call.
		pub(crate) fn is_batch(call: &RuntimeCallOf<T>) -> bool {
			<RuntimeCallOf<T> as IsSubType<Call<T>>>::is_sub_type(call).is_some()
		}

		/// Whether `call` may be dispatched by an item, directly or nested.
		fn item_call_allowed(call: &RuntimeCallOf<T>) -> bool {
			<T as Config>::MultiOriginCallFilter::contains(call) && !Self::is_batch(call)
		}

		/// The hash of the SCALE encoded list of the `(call, origin)` pairs of `items`.
		pub fn items_hash<'a>(
			items: impl IntoIterator<Item = (&'a RuntimeCallOf<T>, &'a PalletsOriginOf<T>)>,
		) -> HashOf<T> {
			<T as frame_system::Config>::Hashing::hash_of(&items.into_iter().collect::<Vec<_>>())
		}

		/// The weight of the pallet's own work for a batch of `count` items encoding to `bytes`.
		pub fn overhead_weight(count: u32, bytes: u32) -> Weight {
			<T as Config>::WeightInfo::batch_multi_origin(count, bytes)
		}

		/// The declared weight of a batch of `items`: the overhead and the items' pipelines and
		/// calls.
		pub fn batch_weight(items: &MultiOriginItemsOf<T>) -> Weight {
			let overhead = Self::overhead_weight(items.len() as u32, items.encoded_size() as u32);
			items.iter().fold(overhead, |weight, item| {
				weight
					.saturating_add(item.extension.weight(&item.call))
					.saturating_add(item.call.get_dispatch_info().call_weight)
			})
		}

		fn do_batch(
			origin: OriginFor<T>,
			items: MultiOriginItemsOf<T>,
			nonce: NonceOf<T>,
			mode: BatchMode,
		) -> DispatchResultWithPostInfo {
			let base = Self::overhead_weight(0, 0);
			let submitter = ensure_signed(origin).map_err(|e| e.with_weight(base))?;
			// `CheckNonce` bumped the nonce of the transaction in `prepare`.
			let bumped = nonce.checked_add(&One::one());
			if bumped != Some(frame_system::Pallet::<T>::account_nonce(&submitter)) {
				return Err(Error::<T>::BadNonce.with_weight(base));
			}
			let count = items.len() as u32;
			let bytes = items.encoded_size() as u32;
			let items_hash = Self::items_hash(items.iter().map(|item| (&item.call, &item.origin)));

			let mut weight = Weight::zero();
			let mut free_weight = Weight::zero();
			let mut free_len = 0u32;
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
				let len = item.encoded_size() as u32;
				let (item_weight, pays, outcome) = Self::apply_item(item, &implication);
				weight = weight.saturating_add(item_weight);
				if pays == Pays::No {
					free_weight = free_weight.saturating_add(item_weight);
					free_len = free_len.saturating_add(len);
				}
				let Err(error) = outcome else {
					Self::deposit_event(Event::ItemCompleted { index });
					continue;
				};
				has_error = true;
				match mode {
					BatchMode::StopAtFailure => {
						Self::deposit_event(Event::BatchInterrupted { index, error });
						break;
					},
					BatchMode::All => Self::deposit_event(Event::ItemFailed { index, error }),
				}
			}
			if !has_error {
				Self::deposit_event(Event::BatchCompleted);
			} else if mode == BatchMode::All {
				Self::deposit_event(Event::BatchCompletedWithErrors);
			}
			if free_len != 0 {
				RefundableShare::<T>::put((free_weight, free_len));
			}
			Ok(Some(Self::overhead_weight(count, bytes).saturating_add(weight)).into())
		}

		/// Apply an item in a storage transaction rolled back if the item is invalid. Returns the
		/// weight the item used, whether its dispatch pays a fee and its outcome.
		fn apply_item(
			item: MultiOriginItemOf<T>,
			implication: &ItemImplication<AccountIdOf<T>, NonceOf<T>, HashOf<T>>,
		) -> (Weight, Pays, Result<(), ItemError>) {
			let mut info = item.call.get_dispatch_info();
			info.extension_weight = item.extension.weight(&item.call);

			let result =
				with_transaction_opaque_err(|| match Self::run_item(item, implication, &info) {
					Err(err) => TransactionOutcome::Rollback(Err(err)),
					Ok(res) => TransactionOutcome::Commit(Ok(res)),
				})
				.unwrap_or_else(|()| {
					Err(RunError::BeforeDispatch(InvalidTransaction::ExhaustsResources.into()))
				});

			match result {
				Err(RunError::BeforeDispatch(err)) => {
					(info.extension_weight, Pays::Yes, Err(ItemError::Invalid(err)))
				},
				// The call ran before the rollback: its declared weight is used and paid for.
				Err(RunError::AfterDispatch(err)) => {
					(info.total_weight(), Pays::Yes, Err(ItemError::Invalid(err)))
				},
				Ok((weight, pays, result)) => (weight, pays, result.map_err(ItemError::Failed)),
			}
		}

		/// Run an item through its pipeline and dispatch its call. Returns the actual weight of
		/// the item, whether it pays a fee and its result.
		fn run_item(
			item: MultiOriginItemOf<T>,
			implication: &ItemImplication<AccountIdOf<T>, NonceOf<T>, HashOf<T>>,
			info: &DispatchInfo,
		) -> Result<(Weight, Pays, Result<(), DispatchError>), RunError> {
			let MultiOriginItem { call, extension, origin: expected } = item;
			if !Self::item_call_allowed(&call) {
				return Err(RunError::BeforeDispatch(InvalidTransaction::Call.into()));
			}
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

			let mut origin: RuntimeOriginOf<T> = origin;
			origin.add_filter(Self::item_call_allowed);
			let mut res = call.dispatch(origin);
			let pd_res = res.map(|_| ()).map_err(|e| e.error);
			let post_info = match &mut res {
				Ok(info) => info,
				Err(err) => &mut err.post_info,
			};
			post_info.set_extension_weight(info);
			<T as Config>::InnerExtension::post_dispatch(pre, info, post_info, 0, &pd_res)
				.map_err(RunError::AfterDispatch)?;
			Ok((post_info.calc_actual_weight(info), post_info.pays_fee(info), pd_res))
		}
	}
}
