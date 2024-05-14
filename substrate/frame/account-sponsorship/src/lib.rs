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

//! # Account sponsorship pallet.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub use pallet::*;

use frame_support::{
	pallet_prelude::*,
	traits::{
		fungible::{hold::Balanced, Inspect, InspectHold, Mutate, MutateHold},
		tokens::Precision,
		Get,
	},
};
use frame_system::pallet_prelude::*;
use sp_runtime::traits::Saturating;
use sp_std::prelude::*;

pub(crate) type BalanceOf<T> =
	<<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

/// TODO
#[derive(
	Encode, Decode, Clone, Copy, PartialEq, Eq, Default, RuntimeDebug, MaxEncodedLen, TypeInfo,
)]
pub struct SponsorStats {
	pub total: u16,
	pub active: u16,
}

impl SponsorStats {
	pub fn new(count: u16) -> Self {
		Self { total: count, active: count }
	}

	pub fn from_parts(total: u16, active: u16) -> Self {
		Self { total, active }
	}
}

#[frame_support::pallet(dev_mode)]
pub mod pallet {
	use super::*;

	#[pallet::config(with_default)]
	pub trait Config: frame_system::Config {
		/// The overarching event type.
		#[pallet::no_default_bounds]
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// The currency provider type.
		#[pallet::no_default]
		type Currency: InspectHold<Self::AccountId>
			+ Mutate<Self::AccountId>
			+ MutateHold<Self::AccountId, Reason = Self::RuntimeHoldReason>
			+ Balanced<Self::AccountId>;

		/// The overarching runtime hold reason.
		#[pallet::no_default_bounds]
		type RuntimeHoldReason: From<HoldReason>;

		/// The amount to be deposited for to allow sponsor one account.
		#[pallet::no_default]
		type AccountDeposit: Get<BalanceOf<Self>>;
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Invalid.
		Invalid,
		/// Not enough.
		NotEnoughFunds,
		/// Not enough sponsorship credit.
		NotEnoughCredit,
		/// Not sponsor.
		NotSponsor,
		/// Not sponsored.
		NotSponsored,
		/// Wrong sponsor.
		WrongSponsor,
		/// Account already exists.
		AlreadyExists,
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(crate) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Sponsor increased their deposit.
		SponsorshipIncreased { who: T::AccountId, old: u16, new: u16 },
		/// Sponsor decreased their deposit.
		SponsorshipDecreased { who: T::AccountId, old: u16, new: u16 },
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// Default implementations of [`DefaultConfig`], which can be used to implement [`Config`].
	pub mod config_preludes {
		use super::*;
		use frame_support::derive_impl;

		pub struct TestDefaultConfig;

		#[derive_impl(frame_system::config_preludes::TestDefaultConfig, no_aggregated_types)]
		impl frame_system::DefaultConfig for TestDefaultConfig {}

		#[frame_support::register_default_impl(TestDefaultConfig)]
		impl DefaultConfig for TestDefaultConfig {
			#[inject_runtime_type]
			type RuntimeEvent = ();
			#[inject_runtime_type]
			type RuntimeHoldReason = ();
		}
	}

	/// Sponsor stats.
	#[pallet::storage]
	pub type Sponsors<T: Config> = StorageMap<_, Twox64Concat, T::AccountId, SponsorStats>;

	/// Sponsor stats.
	#[pallet::storage]
	pub type Beneficiaries<T: Config> = StorageMap<_, Blake2_128, T::AccountId, T::AccountId>;

	/// The reason for this pallet placing a hold on funds.
	#[pallet::composite_enum]
	pub enum HoldReason {
		/// The funds are held as a deposit for sponsoring accounts.
		#[codec(index = 0)]
		AccountSponsorship,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// TODO
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::zero())]
		pub fn deposit_for_accounts(origin: OriginFor<T>, count: u16) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let deposit = Self::calculate_deposit(count);
			T::Currency::hold(&HoldReason::AccountSponsorship.into(), &who, deposit)
				.map_err(|_| <Error<T>>::NotEnoughFunds)?;

			let (old, new) = Sponsors::<T>::mutate(&who, |maybe_stats| {
				let old_stats = maybe_stats.unwrap_or_default();
				let new_stats = SponsorStats::from_parts(
					old_stats.total.saturating_add(count),
					old_stats.active,
				);
				*maybe_stats = Some(new_stats);
				(old_stats.total, new_stats.total)
			});

			Self::deposit_event(Event::<T>::SponsorshipIncreased { who, old, new });

			Ok(())
		}

		/// TODO
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::zero())]
		pub fn withdraw_deposit(origin: OriginFor<T>, count: u16) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let deposit = Self::calculate_deposit(count);
			ensure!(
				T::Currency::balance_on_hold(&HoldReason::AccountSponsorship.into(), &who) >=
					deposit,
				Error::<T>::NotEnoughFunds
			);

			let (old, new) = Sponsors::<T>::try_mutate(&who, |maybe_stats| {
				let old_stats =
					maybe_stats.map(|stats| stats.clone()).ok_or(Error::<T>::NotSponsor)?;
				let new_total =
					old_stats.total.checked_sub(count).ok_or(Error::<T>::NotEnoughFunds)?;
				ensure!(new_total >= old_stats.active, Error::<T>::NotEnoughFunds);
				let new_stats = SponsorStats::from_parts(new_total, old_stats.active);
				*maybe_stats = Some(new_stats);
				Ok::<(u16, u16), Error<T>>((old_stats.total, new_total))
			})?;
			T::Currency::release(
				&HoldReason::AccountSponsorship.into(),
				&who,
				deposit,
				Precision::Exact,
			)
			.map_err(|_| Error::<T>::NotEnoughFunds)?;

			Self::deposit_event(Event::<T>::SponsorshipDecreased { who, old, new });

			Ok(())
		}

		/// TODO
		#[pallet::call_index(2)]
		#[pallet::weight(Weight::zero())]
		pub fn sponsor(origin: OriginFor<T>, target: T::AccountId) -> DispatchResult {
			let who = ensure_signed(origin)?;
			// ensure!(!<frame_system::Pallet<T>::account_exists(&target),
			// Error::<T>::AlreadyExists);
			ensure!(!Sponsors::<T>::contains_key(&target), Error::<T>::Invalid);
			ensure!(!Beneficiaries::<T>::contains_key(&target), Error::<T>::Invalid);

			Sponsors::<T>::try_mutate(&who, |maybe_stats| {
				let mut stats =
					maybe_stats.map(|stats| stats.clone()).ok_or(Error::<T>::NotSponsor)?;
				stats.active = stats.active.saturating_add(1);
				ensure!(stats.active <= stats.total, Error::<T>::NotEnoughCredit);
				*maybe_stats = Some(stats);
				Ok::<(), Error<T>>(())
			})?;
			frame_system::Pallet::<T>::inc_providers(&target);
			Beneficiaries::<T>::insert(target, who);
			Ok(())
		}

		/// TODO
		#[pallet::call_index(3)]
		#[pallet::weight(Weight::zero())]
		pub fn withdraw_sponsorship(origin: OriginFor<T>, target: T::AccountId) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(<frame_system::Pallet<T>>::account_exists(&target), Error::<T>::Invalid);
			ensure!(
				Beneficiaries::<T>::get(&target).ok_or(Error::<T>::NotSponsored)? == who,
				Error::<T>::WrongSponsor
			);
			Sponsors::<T>::try_mutate(&who, |maybe_stats| {
				let mut stats =
					maybe_stats.map(|stats| stats.clone()).ok_or(Error::<T>::NotSponsor)?;
				stats.active = stats.active.checked_sub(1).ok_or(Error::<T>::Invalid)?;
				*maybe_stats = Some(stats);
				Ok::<(), Error<T>>(())
			})?;
			frame_system::Pallet::<T>::dec_providers(&target)?;
			Beneficiaries::<T>::remove(target);
			Ok(())
		}

		/// TODO
		#[pallet::call_index(4)]
		#[pallet::weight(Weight::zero())]
		pub fn todo4(_origin: OriginFor<T>) -> DispatchResult {
			todo!();
		}
	}

	impl<T: Config> Pallet<T> {
		/// Calculate the deposit required for sponsoring the existence of `count` accounts.
		pub fn calculate_deposit(count: u16) -> BalanceOf<T> {
			T::AccountDeposit::get().saturating_mul(count.into())
		}
	}
}
