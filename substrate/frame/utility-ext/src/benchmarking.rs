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

//! Benchmarks for the Utility Extension Pallet.
//!
//! The items are built by [`Config::BenchmarkHelper`] with the real inner pipeline and a real
//! call, so the measured per-item overhead includes one run of that pipeline (signature check,
//! nonce and fee bookkeeping) and the call itself, which the batch also charges separately
//! through the items' declared weights. The overhead is therefore overestimated by roughly one
//! cheap signed transaction per item. This is deliberate: the error is in the safe direction, it
//! is only ever paid by the submitter of a batch call and never by any other transaction, and a
//! benchmark with a weightless pipeline would not exercise the code the batch really runs.

#![cfg(feature = "runtime-benchmarks")]

use alloc::vec::Vec;
use frame_benchmarking::v2::*;
use frame_support::traits::Get;

use crate::*;

fn assert_last_event<T: Config>(generic_event: <T as frame_system::Config>::RuntimeEvent) {
	frame_system::Pallet::<T>::assert_last_event(generic_event.into());
}

/// The origin of the benchmark batches and `c` items of it, each a `remark`, signed for a batch
/// in `mode` of the whitelisted caller with nonce 0.
fn batch<T: Config>(c: u32, mode: BatchMode) -> (Origin<T>, MultiOriginItemsOf<T>) {
	let submitter: T::AccountId = whitelisted_caller();
	let nonce = Default::default();
	let origin = T::BenchmarkHelper::setup();
	let call: RuntimeCallOf<T> = frame_system::Call::<T>::remark { remark: Vec::new() }.into();
	let items_hash = Pallet::<T>::items_hash((0..c).map(|_| (&call, &origin)));
	let items: Vec<_> = (0..c)
		.map(|index| {
			let implication = ItemImplication {
				mode,
				submitter: &submitter,
				nonce,
				index,
				items_hash: &items_hash,
			};
			T::BenchmarkHelper::item(call.clone(), index.into(), implication.encode())
		})
		.collect();
	let items = items.try_into().expect("`c` is bounded by `MaxMultiOriginBatch`; qed");
	(RawOrigin::MultiOriginBatch { submitter, nonce }, items)
}

#[benchmarks]
mod benchmark {
	use super::*;

	#[benchmark]
	fn batch_multi_origin(c: Linear<1, { T::MaxMultiOriginBatch::get() }>) {
		let (origin, items) = batch::<T>(c, BatchMode::Stop);

		#[extrinsic_call]
		_(origin, items);

		assert_last_event::<T>(Event::BatchCompleted.into());
	}

	#[benchmark]
	fn force_batch_multi_origin(c: Linear<1, { T::MaxMultiOriginBatch::get() }>) {
		let (origin, items) = batch::<T>(c, BatchMode::Continue);

		#[extrinsic_call]
		_(origin, items);

		assert_last_event::<T>(Event::BatchCompleted.into());
	}

	impl_benchmark_test_suite! {
		Pallet,
		tests::new_test_ext(),
		tests::Test
	}
}
