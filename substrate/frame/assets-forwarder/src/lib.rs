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

//! Forwards fungible asset definitions to a sibling chain over XCM.
//!
//! Any signed account can replicate an asset of the local registry, [`Config::Assets`], onto the
//! destination chain. The pallet reads the asset's minimum balance and sufficiency from the
//! registry, so a caller cannot misrepresent them, and sends the destination a program that
//! force-creates the replica with this pallet's sovereign account as owner and team. Metadata is
//! not carried over: it can be queried on the chain the asset originates from. The destination
//! authenticates the program by this pallet's location, so its `pallet-assets` instance must set an
//! origin filter (for example `EnsureXcm<Equals<location>>`) that matches `(1, [Parachain(<this
//! chain>), PalletInstance(<this pallet>)])` as `ForceOrigin`.
//!
//! The registry can be a single `pallet-assets` instance or a union of several, such as the local
//! and foreign assets of an Asset Hub. [`Config::AssetIdToLocation`] maps an asset id to its
//! location from this chain's perspective, which the pallet reanchors to the destination to obtain
//! the replica's id. Assets of a local `pallet-assets` instance map to `(0,
//! [PalletInstance(<index>), GeneralIndex(<id>)])`, while assets already identified by a location,
//! such as foreign assets, map to themselves and keep their location on the destination.
//!
//! The replica's owner and team resolve to an account nobody controls on the destination, so its
//! issuance there can only change through XCM transfers backed by this chain. The caller pays the
//! XCM delivery fees. A deposit backs the [`ForwardedAssets`] entry and increases the cost of
//! unsolicited forwards. Only [`Config::ManagerOrigin`] can release the deposit by calling
//! [`Pallet::remove_forwarded_asset`]. The removal is local and does not affect remote chains.
//! Since the replica is created without a deposit on the destination, [`Config::ForwardDeposit`]
//! should be at least the destination's asset deposit.
//!
//! The pallet is pinned to XCM v5: the remote asset ids are v5 locations and the destination must
//! accept v5 programs.
//!
//! Sufficiency and minimum balance can change after an asset was forwarded, so the permissionless
//! [`Pallet::sync_asset_status`] call re-sends the current values for an already forwarded asset.
//! The last-sent values are recorded and a sync that repeats them is rejected, so the destination
//! only executes when there is something to update. The frequency of updates is therefore bounded
//! by status changes, which the asset owner controls. A sync also resets the replica's team to
//! this pallet's sovereign account and unfreezes it, overriding any change the destination's force
//! origin made there.
//!
//! # Remote failures
//!
//! XCM delivery is validated before anything is recorded, so a message that cannot be sent leaves
//! no trace. Execution on the destination happens later and its outcome is not reported back:
//!
//! - A forward that fails on the destination, for example because a replica already exists there,
//!   leaves a [`ForwardedAssets`] entry without a replica. [`Config::ManagerOrigin`] removes the
//!   entry with [`Pallet::remove_forwarded_asset`], after which the asset can be forwarded again
//!   once the destination is ready for it.
//! - A sync that fails on the destination leaves the recorded status ahead of the replica. Since
//!   the destination is a chain under the same governance, its own force origin corrects the
//!   replica directly; the next local status change re-enables [`Pallet::sync_asset_status`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;
pub mod weights;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use pallet::*;
pub use weights::WeightInfo;

use alloc::vec;
use codec::{Encode, HasCompact};
use frame_support::{
	pallet_prelude::*,
	traits::{
		fungible::{Inspect as FungibleInspect, Mutate as FungibleMutate, MutateHold},
		fungibles::Inspect as FungiblesInspect,
		tokens::{DepositConsequence, Precision, Provenance},
	},
};
use sp_runtime::{
	traits::{MaybeEquivalence, TryConvert, Zero},
	MultiAddress,
};
use xcm::v5::{
	validate_send, ExecuteXcm, InteriorLocation, Junction, Location, MaybeErrorCode, OriginKind,
	Reanchorable, SendXcm, WeightLimit, Xcm, XcmHash,
};
use xcm_executor::traits::{ConvertLocation, FeeManager, FeeReason};

/// Balance type of the currency backing the forward deposit.
pub type NativeBalanceOf<T, I> = <<T as Config<I>>::Currency as FungibleInspect<
	<T as frame_system::Config>::AccountId,
>>::Balance;

/// Asset id type of the local asset registry.
pub type AssetIdOf<T, I> =
	<<T as Config<I>>::Assets as FungiblesInspect<<T as frame_system::Config>::AccountId>>::AssetId;

/// Balance type of the local asset registry.
pub type AssetBalanceOf<T, I> =
	<<T as Config<I>>::Assets as FungiblesInspect<<T as frame_system::Config>::AccountId>>::Balance;

/// Record of a forwarded asset.
#[derive(Clone, Debug, Decode, Encode, Eq, MaxEncodedLen, PartialEq, TypeInfo)]
pub struct ForwardInfo<AccountId, Balance, AssetBalance> {
	/// The account that forwarded the asset and pays the deposit.
	pub depositor: AccountId,
	/// The deposit held from the depositor. Recorded here because the configured deposit can
	/// change later.
	pub deposit: Balance,
	/// The asset's minimum balance last sent to the destination.
	pub min_balance: AssetBalance,
	/// The asset's sufficiency last sent to the destination.
	pub is_sufficient: bool,
}

/// Mirror of the destination's `pallet-assets` calls this pallet sends.
///
/// The variant indices are the `pallet-assets` call indices, so the encoding matches the
/// destination without depending on its runtime. The booleans mirror the remote call arguments.
/// The encoding assumes the destination's instance uses `xcm::v5::Location` as asset id
/// parameter, `MultiAddress` lookups over this chain's account id type and a compact-encoded
/// balance.
#[derive(Clone, Debug, Encode, Eq, PartialEq)]
pub enum RemoteAssetsCall<AccountId, Balance: HasCompact> {
	#[codec(index = 1)]
	ForceCreate {
		id: Location,
		owner: MultiAddress<AccountId, ()>,
		is_sufficient: bool,
		#[codec(compact)]
		min_balance: Balance,
	},
	#[codec(index = 21)]
	ForceAssetStatus {
		id: Location,
		owner: MultiAddress<AccountId, ()>,
		issuer: MultiAddress<AccountId, ()>,
		admin: MultiAddress<AccountId, ()>,
		freezer: MultiAddress<AccountId, ()>,
		#[codec(compact)]
		min_balance: Balance,
		is_sufficient: bool,
		is_frozen: bool,
	},
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T, I = ()>(_);

	#[pallet::config]
	pub trait Config<I: 'static = ()>: frame_system::Config {
		/// The overarching hold reason type.
		type RuntimeHoldReason: From<HoldReason<I>>;

		/// Currency the forward deposit is held in.
		type Currency: FungibleMutate<Self::AccountId>
			+ MutateHold<Self::AccountId, Reason = Self::RuntimeHoldReason>;

		/// Registry of the assets that can be forwarded. The minimum balance and sufficiency sent
		/// to the destination are read from it, so whatever it reports is what gets replicated.
		type Assets: FungiblesInspect<Self::AccountId>;

		/// Maps an asset id to its location from this chain's perspective, through the
		/// `convert_back` direction. The location is reanchored to the destination to obtain the
		/// replica's id. Use `xcm_builder::AsPrefixedGeneralIndex` for the ids of a local
		/// `pallet-assets` instance and `sp_runtime::traits::Identity` for assets already
		/// identified by a location.
		type AssetIdToLocation: MaybeEquivalence<Location, AssetIdOf<Self, I>>;

		/// Deposit held from the caller for each forwarded asset. It backs the
		/// [`ForwardedAssets`] entry and is only released when [`Config::ManagerOrigin`] removes
		/// the entry.
		type ForwardDeposit: Get<NativeBalanceOf<Self, I>>;

		/// Origin allowed to remove [`ForwardedAssets`] entries and release their deposits.
		type ManagerOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Location of the destination chain, as seen from this chain.
		type Destination: Get<Location>;

		/// Index of the `pallet-assets` instance in the destination's runtime call enum. The
		/// destination decodes the remote calls under this index, so a mismatch makes every
		/// forward fail on the destination. See [`RemoteAssetsCall`] for the assumptions the
		/// encoding makes about that instance.
		type RemoteAssetsPalletIndex: Get<u8>;

		/// Universal location of this chain, used to reanchor locations to the destination.
		type UniversalLocation: Get<InteriorLocation>;

		/// Converts this pallet's location, as seen from the destination, into the account that
		/// owns the forwarded assets there.
		type DestinationAccountOf: ConvertLocation<Self::AccountId>;

		/// Converts the caller's origin into the location charged for XCM delivery fees.
		type OriginToLocation: TryConvert<Self::RuntimeOrigin, Location>;

		/// Router that delivers XCM to the destination.
		type XcmSender: SendXcm;

		/// Executor used to charge XCM delivery fees to the caller.
		type XcmExecutor: ExecuteXcm<Self::RuntimeCall> + FeeManager;

		/// Weight information for this pallet.
		type WeightInfo: WeightInfo;

		/// Helper for setting up benchmark preconditions only the runtime knows how to create.
		#[cfg(feature = "runtime-benchmarks")]
		type BenchmarkHelper: crate::benchmarking::BenchmarkHelper<AssetIdOf<Self, I>>;
	}

	/// Reasons for holding funds.
	#[pallet::composite_enum]
	pub enum HoldReason<I: 'static = ()> {
		/// Deposit backing a [`ForwardedAssets`] entry.
		#[codec(index = 0)]
		ForwardDeposit,
	}

	/// Assets already forwarded to the destination chain.
	#[pallet::storage]
	pub type ForwardedAssets<T: Config<I>, I: 'static = ()> = StorageMap<
		_,
		Blake2_128Concat,
		AssetIdOf<T, I>,
		ForwardInfo<T::AccountId, NativeBalanceOf<T, I>, AssetBalanceOf<T, I>>,
		OptionQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config<I>, I: 'static = ()> {
		/// An asset was forwarded to the destination chain.
		AssetForwarded {
			asset_id: AssetIdOf<T, I>,
			remote_asset_id: Location,
			depositor: T::AccountId,
			deposit: NativeBalanceOf<T, I>,
			min_balance: AssetBalanceOf<T, I>,
			is_sufficient: bool,
			message_id: XcmHash,
		},
		/// The status of a forwarded asset was re-sent to the destination chain.
		AssetStatusSynced {
			asset_id: AssetIdOf<T, I>,
			min_balance: AssetBalanceOf<T, I>,
			is_sufficient: bool,
			message_id: XcmHash,
		},
		/// A forwarded asset's record was removed and its deposit released to the depositor.
		ForwardRemoved {
			asset_id: AssetIdOf<T, I>,
			depositor: T::AccountId,
			released: NativeBalanceOf<T, I>,
		},
	}

	#[pallet::error]
	pub enum Error<T, I = ()> {
		/// The asset does not exist in the local registry or is being destroyed.
		UnknownAsset,
		/// The asset was already forwarded.
		AlreadyForwarded,
		/// The asset was not forwarded yet.
		NotForwarded,
		/// The asset's status equals what was last sent, so there is nothing to sync.
		StatusUnchanged,
		/// The asset id or the pallet location cannot be expressed from the destination's
		/// perspective.
		InvalidAssetLocation,
		/// A location cannot be converted into an account.
		LocationConversionFailed,
		/// The XCM delivery fees cannot be charged to the caller.
		FeesNotPaid,
		/// The message cannot be delivered to the destination.
		SendFailed,
	}

	#[pallet::call]
	impl<T: Config<I>, I: 'static> Pallet<T, I> {
		/// Forward the asset `id` to the destination chain.
		///
		/// The asset must exist in [`Config::Assets`] and not be in the process of being destroyed.
		/// Its minimum balance and sufficiency are read from there and replicated on the
		/// destination. The caller pays the XCM delivery
		/// fees and [`Config::ForwardDeposit`], which is held until [`Config::ManagerOrigin`]
		/// removes the record.
		#[pallet::call_index(0)]
		#[pallet::weight(<T as Config<I>>::WeightInfo::forward_asset())]
		pub fn forward_asset(origin: OriginFor<T>, id: AssetIdOf<T, I>) -> DispatchResult {
			let who = ensure_signed(origin.clone())?;
			ensure!(!ForwardedAssets::<T, I>::contains_key(&id), Error::<T, I>::AlreadyForwarded);
			Self::ensure_asset_live(&id, &who)?;

			let min_balance = T::Assets::minimum_balance(id.clone());
			let is_sufficient = T::Assets::is_sufficient(id.clone());
			let remote_asset_id = Self::remote_asset_id(id.clone())?;
			let owner = Self::remote_owner_account()?;

			let create = RemoteAssetsCall::ForceCreate {
				id: remote_asset_id.clone(),
				owner: MultiAddress::Id(owner),
				is_sufficient,
				min_balance,
			};

			let deposit = T::ForwardDeposit::get();
			<T as Config<I>>::Currency::hold(
				&HoldReason::<I>::ForwardDeposit.into(),
				&who,
				deposit,
			)?;

			let message = Self::build_remote_xcm(&create);
			let message_id = Self::send_remote_xcm(origin, message)?;

			ForwardedAssets::<T, I>::insert(
				&id,
				ForwardInfo { depositor: who.clone(), deposit, min_balance, is_sufficient },
			);
			Self::deposit_event(Event::AssetForwarded {
				asset_id: id,
				remote_asset_id,
				depositor: who,
				deposit,
				min_balance,
				is_sufficient,
				message_id,
			});
			Ok(())
		}

		/// Re-send the minimum balance and sufficiency of a forwarded asset after they changed.
		///
		/// Permissionless: the values are read from [`Config::Assets`], so any caller sends the
		/// same truth. A call that repeats the last-sent values is rejected, which bounds the
		/// unpaid executions the destination performs to actual status changes. The caller pays
		/// the XCM delivery fees. The replica's team is reset to this pallet's sovereign account
		/// and the replica is unfrozen as a side effect.
		#[pallet::call_index(1)]
		#[pallet::weight(<T as Config<I>>::WeightInfo::sync_asset_status())]
		pub fn sync_asset_status(origin: OriginFor<T>, id: AssetIdOf<T, I>) -> DispatchResult {
			let who = ensure_signed(origin.clone())?;
			let mut record =
				ForwardedAssets::<T, I>::get(&id).ok_or(Error::<T, I>::NotForwarded)?;
			Self::ensure_asset_live(&id, &who)?;

			let min_balance = T::Assets::minimum_balance(id.clone());
			let is_sufficient = T::Assets::is_sufficient(id.clone());
			ensure!(
				record.min_balance != min_balance || record.is_sufficient != is_sufficient,
				Error::<T, I>::StatusUnchanged
			);

			let remote_asset_id = Self::remote_asset_id(id.clone())?;
			let owner = Self::remote_owner_account()?;

			let status = RemoteAssetsCall::ForceAssetStatus {
				id: remote_asset_id,
				owner: MultiAddress::Id(owner.clone()),
				issuer: MultiAddress::Id(owner.clone()),
				admin: MultiAddress::Id(owner.clone()),
				freezer: MultiAddress::Id(owner),
				min_balance,
				is_sufficient,
				is_frozen: false,
			};

			let message = Self::build_remote_xcm(&status);
			let message_id = Self::send_remote_xcm(origin, message)?;

			record.min_balance = min_balance;
			record.is_sufficient = is_sufficient;
			ForwardedAssets::<T, I>::insert(&id, record);

			Self::deposit_event(Event::AssetStatusSynced {
				asset_id: id,
				min_balance,
				is_sufficient,
				message_id,
			});
			Ok(())
		}

		/// Remove the [`ForwardedAssets`] entry of asset `id` and release its deposit to the
		/// depositor.
		///
		/// Only [`Config::ManagerOrigin`] can call this. The removal is local: the replica on the
		/// destination is untouched, so a later re-forward fails there while the replica exists.
		#[pallet::call_index(2)]
		#[pallet::weight(<T as Config<I>>::WeightInfo::remove_forwarded_asset())]
		pub fn remove_forwarded_asset(origin: OriginFor<T>, id: AssetIdOf<T, I>) -> DispatchResult {
			T::ManagerOrigin::ensure_origin(origin)?;
			let record = ForwardedAssets::<T, I>::take(&id).ok_or(Error::<T, I>::NotForwarded)?;

			let released = <T as Config<I>>::Currency::release(
				&HoldReason::<I>::ForwardDeposit.into(),
				&record.depositor,
				record.deposit,
				Precision::BestEffort,
			)?;

			Self::deposit_event(Event::ForwardRemoved {
				asset_id: id,
				depositor: record.depositor,
				released,
			});
			Ok(())
		}
	}

	impl<T: Config<I>, I: 'static> Pallet<T, I> {
		/// Returns this pallet's interior location from its runtime instance index.
		///
		/// The destination's origin filter must match this index.
		pub fn pallet_location() -> InteriorLocation {
			let index = <Self as frame_support::traits::PalletInfoAccess>::index() as u8;
			[Junction::PalletInstance(index)].into()
		}

		/// Fails unless `id` is an asset of [`Config::Assets`] that can still take deposits, which
		/// excludes assets in the process of being destroyed. The amount and provenance are
		/// irrelevant: only the `UnknownAsset` consequence is inspected.
		fn ensure_asset_live(id: &AssetIdOf<T, I>, who: &T::AccountId) -> Result<(), Error<T, I>> {
			match T::Assets::can_deposit(id.clone(), who, Zero::zero(), Provenance::Extant) {
				DepositConsequence::UnknownAsset => Err(Error::<T, I>::UnknownAsset),
				_ => Ok(()),
			}
		}

		/// Returns the location of a local asset from the destination's perspective.
		pub fn remote_asset_id(asset_id: AssetIdOf<T, I>) -> Result<Location, Error<T, I>> {
			T::AssetIdToLocation::convert_back(&asset_id)
				.ok_or(Error::<T, I>::InvalidAssetLocation)?
				.reanchored(&T::Destination::get(), &T::UniversalLocation::get())
				.map_err(|_| Error::<T, I>::InvalidAssetLocation)
		}

		/// Returns the account that owns the forwarded assets on the destination: the sovereign
		/// account of this pallet's location as seen from there.
		pub fn remote_owner_account() -> Result<T::AccountId, Error<T, I>> {
			let pallet_location: Location = Self::pallet_location().into();
			let reanchored = pallet_location
				.reanchored(&T::Destination::get(), &T::UniversalLocation::get())
				.map_err(|_| Error::<T, I>::InvalidAssetLocation)?;
			T::DestinationAccountOf::convert_location(&reanchored)
				.ok_or(Error::<T, I>::LocationConversionFailed)
		}

		/// Builds the program executed on the destination. Execution is unpaid because the
		/// destination trusts this chain; the origin is descended into this pallet's location so
		/// the destination can authenticate the `Transact`. The status check surfaces a failed
		/// dispatch as a failed program.
		fn build_remote_xcm(
			call: &RemoteAssetsCall<T::AccountId, AssetBalanceOf<T, I>>,
		) -> Xcm<()> {
			let encoded = (T::RemoteAssetsPalletIndex::get(), call).encode();
			Xcm(vec![
				xcm::v5::Instruction::UnpaidExecution {
					weight_limit: WeightLimit::Unlimited,
					check_origin: None,
				},
				xcm::v5::Instruction::DescendOrigin(Self::pallet_location()),
				xcm::v5::Instruction::Transact {
					origin_kind: OriginKind::Xcm,
					fallback_max_weight: None,
					call: encoded.into(),
				},
				xcm::v5::Instruction::ExpectTransactStatus(MaybeErrorCode::Success),
			])
		}

		/// Delivers `message` to the destination, charging the delivery fees to `origin` unless
		/// the fee manager waives them.
		fn send_remote_xcm(
			origin: T::RuntimeOrigin,
			message: Xcm<()>,
		) -> Result<XcmHash, DispatchError> {
			let fee_payer = T::OriginToLocation::try_convert(origin)
				.map_err(|_| Error::<T, I>::LocationConversionFailed)?;
			let (ticket, price) = validate_send::<T::XcmSender>(T::Destination::get(), message)
				.map_err(|_| Error::<T, I>::SendFailed)?;
			if !<T::XcmExecutor as FeeManager>::is_waived(Some(&fee_payer), FeeReason::ChargeFees) {
				T::XcmExecutor::charge_fees(fee_payer, price)
					.map_err(|_| Error::<T, I>::FeesNotPaid)?;
			}
			let message_id =
				T::XcmSender::deliver(ticket).map_err(|_| Error::<T, I>::SendFailed)?;
			Ok(message_id)
		}
	}
}
