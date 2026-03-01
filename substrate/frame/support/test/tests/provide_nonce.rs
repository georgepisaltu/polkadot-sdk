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

//! Tests for `#[pallet::provide_nonce(...)]` on pallet origin enum variants.

use frame_support::{
	derive_impl,
	traits::ProvideNonce,
};
use sp_runtime::{generic, traits::BlakeTwo256};

/// Pallet 1: Generic enum origin with `provide_nonce` on some variants.
#[frame_support::pallet(dev_mode)]
pub mod pallet1 {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		pub fn noop(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}

	#[pallet::origin]
	#[derive(
		Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	)]
	pub enum Origin<T: Config> {
		#[pallet::provide_nonce(|who| Some(who.clone()))]
		Member(T::AccountId),
		Admin,
	}
}

/// Pallet 2: Generic enum origin with multiple fields.
#[frame_support::pallet(dev_mode)]
pub mod pallet2 {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		pub fn noop(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}

	#[pallet::origin]
	#[derive(
		Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	)]
	pub enum Origin<T: Config> {
		#[pallet::provide_nonce(|account, _data| Some(account.clone()))]
		WithData(T::AccountId, u32),
		#[pallet::provide_nonce(|_a, _b| None)]
		NoAccount(u32, u64),
	}
}

/// Pallet 3: Non-generic enum origin (governance-style, no `provide_nonce`).
#[frame_support::pallet(dev_mode)]
pub mod pallet3 {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		pub fn noop(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}

	#[pallet::origin]
	#[derive(
		Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	)]
	pub enum Origin {
		StakingAdmin,
		Treasurer,
	}
}

/// Pallet 4: Struct origin (no `provide_nonce` possible).
#[frame_support::pallet(dev_mode)]
pub mod pallet4 {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		pub fn noop(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}

	#[pallet::origin]
	#[derive(
		Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	)]
	pub struct Origin<T>(pub PhantomData<T>);
}

/// Pallet 5: Function reference instead of closure.
#[frame_support::pallet(dev_mode)]
pub mod pallet5 {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		pub fn noop(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		fn nonce_for_member(who: &T::AccountId) -> Option<T::AccountId> {
			Some(who.clone())
		}
	}

	#[pallet::origin]
	#[derive(
		Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	)]
	pub enum Origin<T: Config> {
		#[pallet::provide_nonce(Self::nonce_for_member)]
		Member(T::AccountId),
	}
}

/// Pallet 6: Instanced pallet origin.
#[frame_support::pallet(dev_mode)]
pub mod pallet6 {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T, I = ()>(_);

	#[pallet::config]
	pub trait Config<I: 'static = ()>: frame_system::Config {}

	#[pallet::call]
	impl<T: Config<I>, I: 'static> Pallet<T, I> {
		pub fn noop(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}

	#[pallet::origin]
	#[derive(
		Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	)]
	#[scale_info(skip_type_params(T, I))]
	pub enum Origin<T: Config<I>, I: 'static = ()> {
		#[pallet::provide_nonce(|who| Some(who.clone()))]
		Member(T::AccountId),
		#[allow(dead_code)]
		_Phantom(PhantomData<(T, I)>),
	}
}

/// Pallet 7: Generic enum origin with `provide_nonce` on ALL variants.
#[frame_support::pallet(dev_mode)]
pub mod pallet7 {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		pub fn noop(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}

	#[pallet::origin]
	#[derive(
		Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	)]
	pub enum Origin<T: Config> {
		#[pallet::provide_nonce(|who| Some(who.clone()))]
		Member(T::AccountId),
		#[pallet::provide_nonce(|who, _data| Some(who.clone()))]
		MemberWithData(T::AccountId, u32),
		#[pallet::provide_nonce(|_a, _b| None)]
		Anonymous(u32, u64),
	}
}

/// Pallet 8: Non-generic enum origin with `provide_nonce` on multiple variants.
/// Closures access `Self` (= `Pallet<T>`) to derive AccountId from concrete fields.
#[frame_support::pallet(dev_mode)]
pub mod pallet8 {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	/// Storage mapping from u32 council IDs to AccountIds.
	#[pallet::storage]
	pub type CouncilAccounts<T: Config> =
		StorageMap<_, Twox64Concat, u32, T::AccountId>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		pub fn noop(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		pub fn account_for_council(id: &u32) -> Option<T::AccountId> {
			CouncilAccounts::<T>::get(id)
		}
	}

	#[pallet::origin]
	#[derive(
		Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	)]
	pub enum Origin {
		#[pallet::provide_nonce(|id| Self::account_for_council(id))]
		Council(u32),
		#[pallet::provide_nonce(|_count, _threshold| None)]
		Members(u32, u32),
		TechCommittee,
	}
}

/// Pallet 9: Instanced pallet with a type alias origin (mirrors pallet_collective).
/// The aliased `RawOrigin` implements `ProvideNonce`, so the type alias delegation
/// returns `Some(account)` for the `Member` variant.
#[frame_support::pallet(dev_mode)]
pub mod pallet9 {
	use core::marker::PhantomData;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T, I = ()>(_);

	#[pallet::config]
	pub trait Config<I: 'static = ()>: frame_system::Config {}

	#[pallet::call]
	impl<T: Config<I>, I: 'static> Pallet<T, I> {
		pub fn noop(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}

	/// A collective-style RawOrigin with an instance parameter.
	#[derive(
		Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	)]
	#[scale_info(skip_type_params(I))]
	#[codec(mel_bound(AccountId: MaxEncodedLen))]
	pub enum RawOrigin<AccountId, I> {
		Members(u32, u32),
		Member(AccountId),
		_Phantom(PhantomData<I>),
	}

	impl<AccountId: Clone, I> frame_support::traits::ProvideNonce<AccountId>
		for RawOrigin<AccountId, I>
	{
		fn nonce_provider(&self) -> Option<AccountId> {
			match self {
				RawOrigin::Member(who) => Some(who.clone()),
				_ => None,
			}
		}
	}

	/// Type alias origin, just like pallet_collective.
	#[pallet::origin]
	pub type Origin<T, I = ()> = RawOrigin<<T as frame_system::Config>::AccountId, I>;
}

/// Pallet 10: Type alias origin with a custom type that manually implements `ProvideNonce`.
/// Verifies that `__provide_nonce_for_origin` delegates to the trait impl on the aliased type.
#[frame_support::pallet(dev_mode)]
pub mod pallet10 {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		pub fn noop(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}

	/// A custom origin type with a manual `ProvideNonce` implementation.
	#[derive(
		Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	)]
	pub enum CustomOrigin<AccountId> {
		Admin(AccountId),
		Root,
	}

	impl<AccountId: Clone> frame_support::traits::ProvideNonce<AccountId>
		for CustomOrigin<AccountId>
	{
		fn nonce_provider(&self) -> Option<AccountId> {
			match self {
				CustomOrigin::Admin(who) => Some(who.clone()),
				CustomOrigin::Root => None,
			}
		}
	}

	#[pallet::origin]
	pub type Origin<T> = CustomOrigin<<T as frame_system::Config>::AccountId>;
}

pub type AccountId = u64;
pub type Header = generic::Header<u32, BlakeTwo256>;
pub type UncheckedExtrinsic = generic::UncheckedExtrinsic<u64, RuntimeCall, (), ()>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

frame_support::construct_runtime!(
	pub enum Runtime {
		System: frame_system,
		Pallet1: pallet1,
		Pallet2: pallet2,
		Pallet3: pallet3,
		Pallet4: pallet4,
		Pallet5: pallet5,
		Pallet6: pallet6,
		Pallet6Instance2: pallet6::<Instance2>,
		Pallet7: pallet7,
		Pallet8: pallet8,
		Pallet9: pallet9,
		Pallet9Instance2: pallet9::<Instance2>,
		Pallet10: pallet10,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Runtime {
	type Block = Block;
}

impl pallet1::Config for Runtime {}
impl pallet2::Config for Runtime {}
impl pallet3::Config for Runtime {}
impl pallet4::Config for Runtime {}
impl pallet5::Config for Runtime {}
impl pallet6::Config for Runtime {}
impl pallet6::Config<frame_support::instances::Instance2> for Runtime {}
impl pallet7::Config for Runtime {}
impl pallet8::Config for Runtime {}
impl pallet9::Config for Runtime {}
impl pallet9::Config<frame_support::instances::Instance2> for Runtime {}
impl pallet10::Config for Runtime {}

#[test]
fn test_system_origin_nonce_provider() {
	use frame_system::RawOrigin;

	assert_eq!(OriginCaller::system(RawOrigin::Signed(42)).nonce_provider(), Some(42u64));
	assert_eq!(OriginCaller::system(RawOrigin::Root).nonce_provider(), None);
	assert_eq!(OriginCaller::system(RawOrigin::None).nonce_provider(), None);
}

#[test]
fn test_enum_origin_with_provide_nonce() {
	assert_eq!(
		OriginCaller::Pallet1(pallet1::Origin::Member(42)).nonce_provider(),
		Some(42u64)
	);
	assert_eq!(OriginCaller::Pallet1(pallet1::Origin::Admin).nonce_provider(), None);
}

#[test]
fn test_enum_origin_multiple_fields() {
	assert_eq!(
		OriginCaller::Pallet2(pallet2::Origin::WithData(42, 100)).nonce_provider(),
		Some(42u64)
	);
	assert_eq!(
		OriginCaller::Pallet2(pallet2::Origin::NoAccount(1, 2)).nonce_provider(),
		None
	);
}

#[test]
fn test_non_generic_enum_origin() {
	assert_eq!(
		OriginCaller::Pallet3(pallet3::Origin::StakingAdmin).nonce_provider(),
		None
	);
	assert_eq!(
		OriginCaller::Pallet3(pallet3::Origin::Treasurer).nonce_provider(),
		None
	);
}

#[test]
fn test_struct_origin() {
	use core::marker::PhantomData;

	assert_eq!(
		OriginCaller::Pallet4(pallet4::Origin(PhantomData)).nonce_provider(),
		None
	);
}

#[test]
fn test_function_reference_nonce_provider() {
	assert_eq!(
		OriginCaller::Pallet5(pallet5::Origin::Member(42)).nonce_provider(),
		Some(42u64)
	);
}

#[test]
fn test_instanced_origin_nonce_provider() {
	assert_eq!(
		OriginCaller::Pallet6(pallet6::Origin::Member(42)).nonce_provider(),
		Some(42u64)
	);
	assert_eq!(
		OriginCaller::Pallet6Instance2(pallet6::Origin::Member(42)).nonce_provider(),
		Some(42u64)
	);
}

#[test]
fn test_provide_nonce_trait_directly() {
	assert_eq!(
		ProvideNonce::nonce_provider(&pallet1::Origin::<Runtime>::Member(42)),
		Some(42u64)
	);
	assert_eq!(
		ProvideNonce::nonce_provider(&pallet1::Origin::<Runtime>::Admin),
		None
	);
}

#[test]
fn test_generic_enum_all_variants_provide_nonce() {
	assert_eq!(
		OriginCaller::Pallet7(pallet7::Origin::Member(42)).nonce_provider(),
		Some(42u64)
	);
	assert_eq!(
		OriginCaller::Pallet7(pallet7::Origin::MemberWithData(99, 7)).nonce_provider(),
		Some(99u64)
	);
	assert_eq!(
		OriginCaller::Pallet7(pallet7::Origin::Anonymous(1, 2)).nonce_provider(),
		None
	);
}

#[test]
fn test_non_generic_enum_provide_nonce_with_storage() {
	use sp_runtime::BuildStorage;

	let t = RuntimeGenesisConfig { ..Default::default() }.build_storage().unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| {
		// Insert a council account mapping
		pallet8::CouncilAccounts::<Runtime>::insert(1u32, 42u64);

		// Council origin with existing mapping returns the account
		assert_eq!(
			OriginCaller::Pallet8(pallet8::Origin::Council(1)).nonce_provider(),
			Some(42u64)
		);

		// Council origin without mapping returns None
		assert_eq!(
			OriginCaller::Pallet8(pallet8::Origin::Council(999)).nonce_provider(),
			None
		);

		// Members variant always returns None
		assert_eq!(
			OriginCaller::Pallet8(pallet8::Origin::Members(3, 5)).nonce_provider(),
			None
		);

		// TechCommittee variant (no attribute) returns None
		assert_eq!(
			OriginCaller::Pallet8(pallet8::Origin::TechCommittee).nonce_provider(),
			None
		);
	});
}

#[test]
fn test_existing_pallets_unaffected() {
	// Pallets without #[provide_nonce] (pallet3, pallet4) should compile and return None
	assert_eq!(
		OriginCaller::Pallet3(pallet3::Origin::StakingAdmin).nonce_provider(),
		None
	);
	assert_eq!(
		OriginCaller::Pallet4(pallet4::Origin(core::marker::PhantomData)).nonce_provider(),
		None
	);
}

#[test]
fn test_type_alias_origin_delegates_to_provide_nonce() {
	use pallet9::RawOrigin;

	// pallet9 uses `type Origin<T, I> = RawOrigin<AccountId, I>` (like pallet_collective).
	// The generated __provide_nonce_for_origin delegates to ProvideNonce::nonce_provider
	// on the aliased RawOrigin type, which returns Some for Member variants.
	assert_eq!(
		OriginCaller::Pallet9(RawOrigin::Member(42)).nonce_provider(),
		Some(42u64)
	);
	assert_eq!(
		OriginCaller::Pallet9(RawOrigin::Members(3, 5)).nonce_provider(),
		None
	);

	// Second instance also delegates correctly.
	assert_eq!(
		OriginCaller::Pallet9Instance2(RawOrigin::Member(99)).nonce_provider(),
		Some(99u64)
	);
}

#[test]
fn test_type_alias_custom_origin_with_manual_provide_nonce() {
	use pallet10::CustomOrigin;

	// pallet10 uses `type Origin<T> = CustomOrigin<AccountId>` with a manual
	// ProvideNonce impl. The delegation should return Some for Admin variants.
	assert_eq!(
		OriginCaller::Pallet10(CustomOrigin::Admin(42)).nonce_provider(),
		Some(42u64)
	);
	assert_eq!(
		OriginCaller::Pallet10(CustomOrigin::Root).nonce_provider(),
		None
	);
}
