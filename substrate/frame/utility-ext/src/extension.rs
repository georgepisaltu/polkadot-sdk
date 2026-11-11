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

//! The transaction extension of multi-origin batches and the implication their items sign.
//!
//! - [`MultiOriginBatch`] goes in the runtime's pipeline before its fee payment extension. It
//!   authorizes multi-origin batch transactions and charges their submitter for their share of the
//!   batch.
//! - [`ItemImplication`] is the base implication of every item, and therefore part of its signing
//!   payload.

use crate::{
	AccountIdOf, BatchMode, Config, MultiOriginItemsOf, NonceOf, Pallet, RawOrigin, RefundableShare,
};
use codec::{Decode, DecodeWithMemTracking, Encode};
use core::{fmt, marker::PhantomData};
use frame_support::{
	dispatch::{DispatchInfo, Pays, PostDispatchInfo},
	pallet_prelude::TransactionSource,
	traits::{Imbalance, OriginTrait, SuppressedDrop},
	CloneNoBound, DefaultNoBound, EqNoBound, PartialEqNoBound,
};
use pallet_transaction_payment::{
	ChargeTransactionPayment, OnChargeTransaction, TxCreditHold, WeightInfo as _,
};
use scale_info::TypeInfo;
use sp_runtime::{
	traits::{
		CheckedAdd, Implication, One, PostDispatchInfoOf, TransactionExtension, ValidateResult,
		Zero,
	},
	transaction_validity::{InvalidTransaction, TransactionValidityError, ValidTransaction},
	DispatchResult, Weight,
};

type RuntimeCallOf<T> = <T as frame_system::Config>::RuntimeCall;
type RuntimeOriginOf<T> = <T as frame_system::Config>::RuntimeOrigin;
type PaymentOf<T> = <T as pallet_transaction_payment::Config>::OnChargeTransaction;
type BalanceOf<T> = <PaymentOf<T> as OnChargeTransaction<T>>::Balance;
type LiquidityInfoOf<T> = <PaymentOf<T> as OnChargeTransaction<T>>::LiquidityInfo;
/// The credit `pallet_transaction_payment` keeps a withdrawn fee in.
type CreditOf<T> = <<PaymentOf<T> as TxCreditHold<T>>::Credit as SuppressedDrop>::Inner;

/// Leads the encoding of [`ItemImplication`], so that it does not encode like the implication of
/// a regular transaction, `(extension_version, call)`, for any realistic extension version and
/// pallet index.
pub const ITEM_IMPLICATION_PREFIX: &[u8; 8] = b"_mbatch_";

/// The implication an item is validated with, in place of the usual `(extension_version, call)`.
///
/// It binds the item to its batch: an item cannot be applied alone, in another batch, in a batch
/// of the other mode, next to other parties than the ones it was signed for, or in a batch
/// submitted by another account or by the same account as another one of its transactions.
///
/// It encodes as [`ITEM_IMPLICATION_PREFIX`] followed by the SCALE encoding of its fields in
/// order.
pub struct ItemImplication<'a, AccountId, Nonce, Hash> {
	/// The mode of the batch.
	pub mode: BatchMode,
	/// The account submitting the batch.
	pub submitter: &'a AccountId,
	/// The nonce of the submitter's batch transaction.
	pub nonce: Nonce,
	/// The position of the item in the batch.
	pub index: u32,
	/// The hash of the calls and origins of all items, see
	/// [`Pallet::items_hash`](crate::Pallet::items_hash).
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

/// The [`TransactionExtension::Val`] of [`MultiOriginBatch`].
pub enum Val<AccountId, Nonce, Balance> {
	/// Not a multi-origin batch transaction.
	Other,
	/// A multi-origin batch transaction: its submitter, their nonce, the dispatch info of the
	/// submitter's share and the fee it costs.
	Batch { submitter: AccountId, nonce: Nonce, share: DispatchInfo, fee: Balance },
}

/// The [`TransactionExtension::Pre`] of [`MultiOriginBatch`].
pub enum Pre<T: Config + pallet_transaction_payment::Config> {
	/// Not a multi-origin batch transaction.
	Other,
	/// A multi-origin batch transaction whose share was withdrawn and is settled after dispatch.
	Batch {
		submitter: AccountIdOf<T>,
		/// The dispatch info the share was withdrawn for.
		share: DispatchInfo,
		/// The withdrawn fee, kept out of the transient fee credit while the items run.
		parked: Option<CreditOf<T>>,
		liquidity_info: LiquidityInfoOf<T>,
	},
}

/// Transaction extension authorizing multi-origin batch transactions and charging their
/// submitter for their share of the batch.
///
/// It goes in the runtime's pipeline after `CheckNonce` and before the fee payment extension.
/// For any transaction other than a multi-origin batch it does nothing.
///
/// For a multi-origin batch, submitted as a regular signed transaction:
/// - `validate` checks the items statically (see [`Pallet::check_items`]), checks that the
///   submitter can pay the fee of their share, see [`Pallet::submitter_weight`], computed like
///   `pallet_transaction_payment` does, gives the transaction the priority that fee earns for the
///   batch's full weight, and replaces the signed origin with [`RawOrigin::MultiOriginBatch`],
///   carrying the submitter and their current nonce, so that only this extension can dispatch the
///   batch calls. The fee payment extension after it sees that origin and charges nothing; its tip
///   is ignored.
/// - `prepare` withdraws the fee through the runtime's `OnChargeTransaction` and takes it out of
///   the transient fee credit of `pallet_transaction_payment`, so that the items find it empty and
///   settle their own fee payments without touching the submitter's. It also checks that the
///   submitter's nonce was bumped and rejects the batch otherwise, since a batch whose nonce is not
///   checked could be replayed.
/// - `post_dispatch` puts the fee back and settles it, refunding the submitter the part of the
///   share made refundable by the items, see [`RefundableShare`]: the pipeline weight and bytes of
///   the items whose dispatch returned `Pays::No`. Nothing else is refunded, whatever the items do.
///
/// The submitter pays in the native currency. `CheckWeight` is unaffected: it sees the batch's
/// full weight, items included. The share includes the weight of the fee payment extension,
/// although that extension refunds it for batches. The extension weighs nothing for other
/// transactions; for a batch its weight is that of `ChargeTransactionPayment`, as it does the
/// same work. [`RefundableShare`] is transient and not accounted for.
#[derive(
	Encode,
	Decode,
	DecodeWithMemTracking,
	CloneNoBound,
	EqNoBound,
	PartialEqNoBound,
	DefaultNoBound,
	TypeInfo,
)]
#[scale_info(skip_type_params(T))]
pub struct MultiOriginBatch<T>(PhantomData<T>);

impl<T> fmt::Debug for MultiOriginBatch<T> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "MultiOriginBatch")
	}
}

impl<T> MultiOriginBatch<T> {
	/// Create a new extension.
	pub fn new() -> Self {
		Self(PhantomData)
	}
}

impl<T: Config + pallet_transaction_payment::Config> MultiOriginBatch<T> {
	/// The dispatch info of the submitter's share of a batch of `items`, given the batch's.
	fn submitter_info(
		items: &MultiOriginItemsOf<T>,
		mode: BatchMode,
		info: &DispatchInfo,
	) -> DispatchInfo {
		DispatchInfo {
			call_weight: Pallet::<T>::submitter_weight(items, mode),
			extension_weight: info.extension_weight,
			class: info.class,
			pays_fee: info.pays_fee,
		}
	}

	/// What the submitter of the batch transaction `uxt` of `len` bytes pays for: the weight
	/// and class of their share and its fee, before any refund for items which turn out to be
	/// free. `None` if `uxt` is not a batch. The counterpart of
	/// `pallet_transaction_payment::Pallet::query_info`, which prices the whole batch.
	pub fn query_share_info<Xt>(
		uxt: &Xt,
		len: u32,
	) -> Option<pallet_transaction_payment::RuntimeDispatchInfo<BalanceOf<T>>>
	where
		Xt: sp_runtime::traits::ExtrinsicCall<Call = RuntimeCallOf<T>>
			+ frame_support::dispatch::GetDispatchInfo,
	{
		let (items, mode) = Pallet::<T>::batch_items(uxt.call())?;
		let share = Self::submitter_info(items, mode, &uxt.get_dispatch_info());
		let partial_fee =
			pallet_transaction_payment::Pallet::<T>::compute_fee(len, &share, Zero::zero());
		Some(pallet_transaction_payment::RuntimeDispatchInfo {
			weight: share.total_weight(),
			class: share.class,
			partial_fee,
		})
	}
}

impl<T: Config + pallet_transaction_payment::Config + Send + Sync>
	TransactionExtension<RuntimeCallOf<T>> for MultiOriginBatch<T>
where
	CreditOf<T>: Imbalance<BalanceOf<T>>,
{
	const IDENTIFIER: &'static str = "MultiOriginBatch";
	type Implicit = ();
	type Val = Val<AccountIdOf<T>, NonceOf<T>, BalanceOf<T>>;
	type Pre = Pre<T>;

	fn weight(&self, call: &RuntimeCallOf<T>) -> Weight {
		if Pallet::<T>::batch_items(call).is_none() {
			return Weight::zero();
		}
		// Charging like the fee payment extension; `RefundableShare` is whitelisted.
		<T as pallet_transaction_payment::Config>::WeightInfo::charge_transaction_payment()
	}

	fn validate(
		&self,
		origin: RuntimeOriginOf<T>,
		call: &RuntimeCallOf<T>,
		info: &DispatchInfo,
		len: usize,
		_self_implicit: Self::Implicit,
		_inherited_implication: &impl Implication,
		_source: TransactionSource,
	) -> ValidateResult<Self::Val, RuntimeCallOf<T>> {
		let Some((items, mode)) = Pallet::<T>::batch_items(call) else {
			return Ok((ValidTransaction::default(), Val::Other, origin));
		};

		// Only signed transactions can be multi-origin batches: someone has to pay.
		let submitter = origin.as_signer().cloned().ok_or(InvalidTransaction::BadSigner)?;
		Pallet::<T>::check_items(items)?;

		let share = Self::submitter_info(items, mode, info);
		let tip = Zero::zero();
		let fee = pallet_transaction_payment::Pallet::<T>::compute_fee(len as u32, &share, tip);
		PaymentOf::<T>::can_withdraw_fee(&submitter, call, &share, fee, tip)?;
		// The batch takes its full weight in the block, so the fee earns the priority of that
		// weight, not the share's.
		let priority = ChargeTransactionPayment::<T>::get_priority(info, len, tip, fee);

		// `CheckNonce` only bumps the nonce in `prepare`, so this is the nonce of the transaction.
		let nonce = frame_system::Pallet::<T>::account_nonce(&submitter);
		let origin: RuntimeOriginOf<T> =
			RawOrigin::MultiOriginBatch { submitter: submitter.clone(), nonce }.into();
		let validity = ValidTransaction { priority, ..Default::default() };
		Ok((validity, Val::Batch { submitter, nonce, share, fee }, origin))
	}

	fn prepare(
		self,
		val: Self::Val,
		_origin: &RuntimeOriginOf<T>,
		call: &RuntimeCallOf<T>,
		_info: &DispatchInfo,
		_len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		let Val::Batch { submitter, nonce, share, fee } = val else { return Ok(Pre::Other) };
		// `CheckNonce::prepare` must have run by now, or the batch could be replayed.
		let bumped = nonce.checked_add(&One::one()).unwrap_or_else(Zero::zero);
		if frame_system::Pallet::<T>::account_nonce(&submitter) != bumped {
			log::error!(
				target: "runtime::utility-ext",
				"The submitter's nonce was not bumped before `MultiOriginBatch::prepare`: \
				the extension must come after `CheckNonce` in the pipeline.",
			);
			return Err(InvalidTransaction::BadSigner.into());
		}

		// A fee payment extension placed before this one would have charged the submitter the
		// batch's full fee already.
		if !pallet_transaction_payment::Pallet::<T>::remaining_txfee::<BalanceOf<T>>().is_zero() {
			log::error!(
				target: "runtime::utility-ext",
				"A fee was withdrawn before `MultiOriginBatch::prepare`: the extension must come \
				before the fee payment extension in the pipeline.",
			);
			return Err(InvalidTransaction::Payment.into());
		}

		// Only what this dispatch makes refundable counts.
		RefundableShare::<T>::kill();
		let tip = Zero::zero();
		let liquidity_info = PaymentOf::<T>::withdraw_fee(&submitter, call, &share, fee, tip)?;
		// Keep the withdrawn fee out of the transient fee credit while the items run their own
		// payments, which settle whatever that credit holds.
		let parked = pallet_transaction_payment::Pallet::<T>::withdraw_txfee(
			pallet_transaction_payment::Pallet::<T>::remaining_txfee::<BalanceOf<T>>(),
		);
		Ok(Pre::Batch { submitter, share, parked, liquidity_info })
	}

	fn post_dispatch_details(
		pre: Self::Pre,
		_info: &DispatchInfo,
		_post_info: &PostDispatchInfoOf<RuntimeCallOf<T>>,
		len: usize,
		_result: &DispatchResult,
	) -> Result<Weight, TransactionValidityError> {
		let (submitter, share, parked, liquidity_info) = match pre {
			Pre::Other => return Ok(Weight::zero()),
			Pre::Batch { submitter, share, parked, liquidity_info } => {
				(submitter, share, parked, liquidity_info)
			},
		};
		// Refund the pipelines and bytes of the items which were free.
		let (free_weight, free_len) = RefundableShare::<T>::take().unwrap_or_default();
		let paid_for =
			DispatchInfo { call_weight: share.call_weight.saturating_sub(free_weight), ..share };
		let paid_len = (len as u32).saturating_sub(free_len);
		let tip = Zero::zero();
		let fee = pallet_transaction_payment::Pallet::<T>::compute_fee(paid_len, &paid_for, tip);

		if let Some(credit) = parked {
			pallet_transaction_payment::Pallet::<T>::deposit_txfee(credit);
		}
		let paid = PostDispatchInfo { actual_weight: None, pays_fee: Pays::Yes };
		PaymentOf::<T>::correct_and_deposit_fee(
			&submitter,
			&share,
			&paid,
			fee,
			tip,
			liquidity_info,
		)?;
		pallet_transaction_payment::Pallet::<T>::deposit_fee_paid_event(submitter, fee, tip);
		Ok(Weight::zero())
	}
}
