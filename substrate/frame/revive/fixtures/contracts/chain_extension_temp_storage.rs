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

//! Call chain extension two times with the specified func_ids
//! It then calls itself once
#![no_std]
#![no_main]
include!("../panic_handler.rs");

use uapi::{input, HostFn, HostFnImpl as api};

#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {}

#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
	input!(
		input,
		func_id1: u32,
		func_id2: u32,
		stop_recurse: u8,
	);

	api::call_chain_extension(func_id1, input, None);
	api::call_chain_extension(func_id2, input, None);

	if stop_recurse == 0 {
		// Setup next call
		input[0..4].copy_from_slice(&((3 << 16) | 2u32).to_le_bytes());
		input[4..8].copy_from_slice(&((3 << 16) | 3u32).to_le_bytes());
		input[8] = 1u8;

		// Read the contract address.
		let mut addr = [0u8; 20];
		api::address(&mut addr);

		// call self
		api::call(
			uapi::CallFlags::ALLOW_REENTRY,
			&addr,
			u64::MAX,       // How much ref_time to devote for the execution. u64::MAX = use all.
			u64::MAX,       // How much proof_size to devote for the execution. u64::MAX = use all.
			&[u8::MAX; 32], // No deposit limit.
			&[0u8; 32],     // Value transferred to the contract.
			input,
			None,
		)
		.unwrap();
	}
}
