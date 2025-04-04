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

use frame_benchmarking::v2::*;

#[frame_support::pallet]
mod pallet {
	use frame_system::pallet_prelude::*;
	use frame_support::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::default())]
		pub fn call_1(_origin: OriginFor<T>) -> DispatchResult {
			Ok(())
		}
	}
}

pub use pallet::*;

#[benchmarks]
mod benches {
	use super::*;
	use frame_support::traits::OriginTrait;

	#[benchmark]
	fn call_1() {
		let origin = 3u8;
		#[extrinsic_call]
		_(origin);
	}
}

fn main() {}
