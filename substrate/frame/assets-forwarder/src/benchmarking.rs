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

//! Benchmarks for the assets forwarder.
//!
//! The benchmarks create their asset through `fungibles::Create`, so the runtime's
//! [`Config::Assets`] must implement it when the `runtime-benchmarks` feature is enabled.

use super::*;

use frame_benchmarking::v2::{instance_benchmarks, *};
use frame_support::traits::{
	fungible::{InspectHold, Mutate},
	fungibles::Create,
};
use frame_system::RawOrigin;
use sp_runtime::traits::{Saturating, Zero};

/// What the benchmarks cannot set up themselves, because only the runtime knows how its assets
/// are identified and how its XCM channels are made.
pub trait BenchmarkHelper<AssetId> {
	/// Returns the id under which the benchmarks create their asset in [`Config::Assets`]. For
	/// the worst case, return the id whose location has the most junctions.
	fn asset_id(seed: u32) -> AssetId;

	/// Prepares delivery to the destination chain so the router accepts messages.
	///
	/// Opening the channel is the minimum. For the worst case, also send a message to the
	/// destination beforehand: delivery then finds an existing outbound page, which costs an
	/// extra storage read compared to an empty queue.
	fn open_destination_channel() {}
}

impl<AssetId: From<u32>> BenchmarkHelper<AssetId> for () {
	fn asset_id(seed: u32) -> AssetId {
		seed.into()
	}
}

/// Creates a sufficient asset with minimum balance one, with `caller` funded to pay the forward
/// deposit and the delivery fees.
fn setup_asset<T: Config<I>, I: 'static>(
	caller: &T::AccountId,
) -> Result<AssetIdOf<T, I>, BenchmarkError>
where
	T::Assets: Create<T::AccountId>,
{
	<T as Config<I>>::BenchmarkHelper::open_destination_channel();
	let id = <T as Config<I>>::BenchmarkHelper::asset_id(1);
	let balance = <T as Config<I>>::Currency::minimum_balance()
		.saturating_add(T::ForwardDeposit::get())
		.saturating_mul(1_000_000u32.into());
	<T as Config<I>>::Currency::set_balance(caller, balance);
	T::Assets::create(id.clone(), caller.clone(), true, 1u32.into())
		.map_err(|_| BenchmarkError::Stop("failed to create asset"))?;
	Ok(id)
}

#[instance_benchmarks(where T::Assets: Create<T::AccountId>)]
mod benches {
	use super::*;

	#[benchmark]
	fn forward_asset() -> Result<(), BenchmarkError> {
		let caller: T::AccountId = whitelisted_caller();
		let id = setup_asset::<T, I>(&caller)?;

		#[extrinsic_call]
		_(RawOrigin::Signed(caller), id.clone());

		assert!(ForwardedAssets::<T, I>::contains_key(id));
		Ok(())
	}

	#[benchmark]
	fn sync_asset_status() -> Result<(), BenchmarkError> {
		let caller: T::AccountId = whitelisted_caller();
		let id = setup_asset::<T, I>(&caller)?;
		Pallet::<T, I>::forward_asset(RawOrigin::Signed(caller.clone()).into(), id.clone())
			.map_err(|_| BenchmarkError::Stop("failed to forward asset"))?;
		// Make the record lag behind the registry, otherwise the sync is rejected as a no-op.
		ForwardedAssets::<T, I>::mutate(&id, |record| {
			if let Some(record) = record {
				record.is_sufficient = false;
			}
		});

		#[extrinsic_call]
		_(RawOrigin::Signed(caller), id.clone());

		let record = ForwardedAssets::<T, I>::get(&id).expect("asset is forwarded");
		assert_eq!(record.min_balance, T::Assets::minimum_balance(id.clone()));
		assert_eq!(record.is_sufficient, T::Assets::is_sufficient(id));
		assert!(record.is_sufficient);
		Ok(())
	}

	#[benchmark]
	fn remove_forwarded_asset() -> Result<(), BenchmarkError> {
		let caller: T::AccountId = whitelisted_caller();
		let id = setup_asset::<T, I>(&caller)?;
		Pallet::<T, I>::forward_asset(RawOrigin::Signed(caller.clone()).into(), id.clone())
			.map_err(|_| BenchmarkError::Stop("failed to forward asset"))?;
		let origin =
			T::ManagerOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

		#[extrinsic_call]
		_(origin as T::RuntimeOrigin, id.clone());

		assert!(!ForwardedAssets::<T, I>::contains_key(id));
		assert!(<T as Config<I>>::Currency::balance_on_hold(
			&HoldReason::<I>::ForwardDeposit.into(),
			&caller
		)
		.is_zero());
		Ok(())
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);

	/// The suite above only covers the default instance; this runs the same benchmarks for the
	/// instance over the union of local and foreign assets.
	#[cfg(test)]
	#[test]
	fn union_instance_benchmarks() {
		use crate::mock::{new_test_ext, Test, UnionForwarderInstance};
		use frame_benchmarking::Benchmarking;

		new_test_ext().execute_with(|| {
			for benchmark in Pallet::<Test, UnionForwarderInstance>::benchmarks(true) {
				Pallet::<Test, UnionForwarderInstance>::test_bench_by_name(&benchmark.name)
					.unwrap_or_else(|e| {
						panic!(
							"{} failed: {:?}",
							core::str::from_utf8(&benchmark.name).expect("valid name"),
							e
						)
					});
			}
		});
	}
}
