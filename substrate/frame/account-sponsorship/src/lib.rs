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
use frame_system::{pallet_prelude::*, DecRefStatus};
use sp_runtime::traits::{AccountExistenceProvider, Saturating};
use sp_std::prelude::*;

pub(crate) type BalanceOf<T> =
	<<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

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

		/// The amount to be deposited for registering as an account sponsor.
		#[pallet::no_default]
		type BaseDeposit: Get<BalanceOf<Self>>;

		/// The amount to be deposited for each sponsored account.
		#[pallet::no_default]
		type BeneficiaryDeposit: Get<BalanceOf<Self>>;
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Invalid.
		Invalid,
		/// Not enough.
		NotEnoughFunds,
		/// Not sponsor.
		NotSponsor,
		/// Not sponsored.
		NotSponsored,
		/// Wrong sponsor.
		WrongSponsor,
		// /// Account already exists.
		// AlreadyExists,
		/// Beneficiary account would be reaped without sponsorship.
		Dependent,
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(crate) fn deposit_event)]
	pub enum Event<T: Config> {
		/// TODO.
		Dummy,
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

	#[pallet::type_value]
	pub fn DepositOnEmpty<T: Config>() -> BalanceOf<T> {
		T::Currency::minimum_balance()
	}

	/// The amount to be held to provide for an accounts existence. Defaults to the existential
	/// deposit of the underlying currency type.
	#[pallet::storage]
	pub type AccountDeposit<T: Config> =
		StorageValue<_, BalanceOf<T>, ValueQuery, DepositOnEmpty<T>>;

	/// Map of sponsors and their respective beneficiary count.
	#[pallet::storage]
	pub type Sponsors<T: Config> = StorageMap<_, Twox64Concat, T::AccountId, u16>;

	/// Map of the beneficiaries and their respective sponsors.
	#[pallet::storage]
	pub type Beneficiaries<T: Config> = StorageMap<_, Blake2_128, T::AccountId, T::AccountId>;

	/// The reason for this pallet placing a hold on funds.
	#[pallet::composite_enum]
	pub enum HoldReason {
		/// The funds are held as a deposit for registering as an account sponsor.
		#[codec(index = 0)]
		SponsorshipDeposit,
		/// The funds are held as a deposit for sponsoring a beneficiary account.
		#[codec(index = 1)]
		BeneficiaryDeposit,
		/// The funds are held as an existential deposit for a beneficiary account.
		#[codec(index = 2)]
		ExistentialDeposit,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Sponsor an account's existence by placing a deposit in this pallet.
		///
		/// The deposit is calculated as follows:
		/// - if there is at least one beneficiary associated with a sponsor, then `T::BaseDeposit`
		///   is held to account for the entry in `Sponsors<T>`;
		/// - for each beneficiary, `T::BeneficiaryDeposit` is held to account for the entry in
		///   `Beneficiaries<T>`;
		/// - for each beneficiary, `ExistentialDeposit<T>` is held to provide for the account's
		///   existence and storing its nonce.
		///
		/// Accounts can only have one sponsor at a time. Also, sponsored accounts cannot themselves
		/// sponsor other accounts.
		#[pallet::call_index(2)]
		#[pallet::weight(Weight::zero())]
		pub fn sponsor(origin: OriginFor<T>, target: T::AccountId) -> DispatchResult {
			let who = ensure_signed(origin)?;
			// ensure!(!<frame_system::Pallet<T>::account_exists(&target),
			// Error::<T>::AlreadyExists);
			ensure!(!Sponsors::<T>::contains_key(&target), Error::<T>::Invalid);
			ensure!(!Beneficiaries::<T>::contains_key(&target), Error::<T>::Invalid);

			Self::add_beneficiary(&who, &target)?;

			Ok(())
		}

		/// Withdraw sponsorship for an account's existence, releasing the associated deposit. The
		/// beneficiary's account might be reaped if the sponsorship is its only provider.
		#[pallet::call_index(3)]
		#[pallet::weight(Weight::zero())]
		pub fn withdraw_sponsorship(origin: OriginFor<T>, target: T::AccountId) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(<frame_system::Pallet<T>>::account_exists(&target), Error::<T>::Invalid);
			ensure!(
				Beneficiaries::<T>::get(&target).ok_or(Error::<T>::NotSponsored)? == who,
				Error::<T>::WrongSponsor
			);

			Self::remove_beneficiary(&who, &target, true)?;

			Ok(())
		}

		/// Remove an account as a beneficiary of an account existence sponsorship.
		///
		/// This will fail if the account cannot exist independently after the sponsorship is
		/// removed.
		#[pallet::call_index(5)]
		#[pallet::weight(Weight::zero())]
		pub fn become_independent(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let sponsor = Beneficiaries::<T>::get(&who).ok_or(Error::<T>::NotSponsored)?;

			Self::remove_beneficiary(&sponsor, &who, false)?;

			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		// Convenience function to hold both the beneficiary and existential deposits for an
		// account.
		fn hold_deposit(who: &T::AccountId) -> Result<(), Error<T>> {
			T::Currency::hold(
				&HoldReason::BeneficiaryDeposit.into(),
				who,
				T::BeneficiaryDeposit::get(),
			)
			.map_err(|_| <Error<T>>::NotEnoughFunds)?;
			T::Currency::hold(
				&HoldReason::ExistentialDeposit.into(),
				who,
				AccountDeposit::<T>::get(),
			)
			.map_err(|_| <Error<T>>::NotEnoughFunds)?;
			Ok(())
		}

		// Convenience function to release both the beneficiary and existential deposits for an
		// account.
		fn release_deposit(who: &T::AccountId) -> Result<(), Error<T>> {
			T::Currency::release(
				&HoldReason::BeneficiaryDeposit.into(),
				who,
				T::BeneficiaryDeposit::get(),
				Precision::Exact,
			)
			.map_err(|_| <Error<T>>::NotEnoughFunds)?;
			T::Currency::release(
				&HoldReason::ExistentialDeposit.into(),
				who,
				AccountDeposit::<T>::get(),
				Precision::Exact,
			)
			.map_err(|_| <Error<T>>::NotEnoughFunds)?;
			Ok(())
		}

		fn add_beneficiary(sponsor: &T::AccountId, beneficiary: &T::AccountId) -> DispatchResult {
			Sponsors::<T>::try_mutate(&sponsor, |maybe_beneficiary_count| {
				let mut beneficiary_count = match maybe_beneficiary_count {
					Some(count) => *count,
					None => {
						T::Currency::hold(
							&HoldReason::SponsorshipDeposit.into(),
							&sponsor,
							T::BaseDeposit::get(),
						)
						.map_err(|_| <Error<T>>::NotEnoughFunds)?;
						0
					},
				};
				beneficiary_count.saturating_inc();
				*maybe_beneficiary_count = Some(beneficiary_count);
				Ok::<(), Error<T>>(())
			})?;
			Self::hold_deposit(&sponsor)?;
			frame_system::Pallet::<T>::inc_providers(&beneficiary);
			Beneficiaries::<T>::insert(beneficiary, sponsor);
			Ok(())
		}

		fn remove_beneficiary(
			sponsor: &T::AccountId,
			beneficiary: &T::AccountId,
			expendable: bool,
		) -> DispatchResult {
			Sponsors::<T>::try_mutate(&sponsor, |maybe_beneficiary_count| {
				let mut beneficiary_count =
					maybe_beneficiary_count.ok_or(Error::<T>::NotSponsor)?;
				beneficiary_count = beneficiary_count.checked_sub(1).ok_or(Error::<T>::Invalid)?;
				*maybe_beneficiary_count = if beneficiary_count == 0 {
					T::Currency::release(
						&HoldReason::SponsorshipDeposit.into(),
						&sponsor,
						T::BaseDeposit::get(),
						Precision::Exact,
					)
					.map_err(|_| <Error<T>>::Invalid)?;
					None
				} else {
					Some(beneficiary_count)
				};
				Ok::<(), Error<T>>(())
			})?;

			match frame_system::Pallet::<T>::dec_providers(&beneficiary)? {
				DecRefStatus::Reaped if !expendable => return Err(Error::<T>::Dependent.into()),
				_ => (),
			}
			Self::release_deposit(sponsor)?;
			Beneficiaries::<T>::remove(beneficiary);
			Ok(())
		}
	}

	impl<T: Config> AccountExistenceProvider<T::AccountId> for Pallet<T> {
		fn provide(provider: &T::AccountId, beneficiary: &T::AccountId) -> DispatchResult {
			ensure!(!Sponsors::<T>::contains_key(beneficiary), Error::<T>::Invalid);
			ensure!(!Beneficiaries::<T>::contains_key(beneficiary), Error::<T>::Invalid);
			Self::add_beneficiary(provider, beneficiary)
		}
	}
}