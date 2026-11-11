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

//! Runtime API for building multi-origin batches.

use crate::{BatchMode, ItemExtension};
use alloc::vec::Vec;
use codec::Codec;
use pallet_transaction_payment::RuntimeDispatchInfo;

sp_api::decl_runtime_apis! {
	/// What wallets need to build a multi-origin batch: the item pipeline's data, the payload
	/// each item's origin authorizes and what the submitter pays.
	///
	/// `Call`, `PalletsOrigin` and `Extension` are the runtime's call, the `PalletsOrigin` of its
	/// origin and the item pipeline, `Config::InnerExtension`.
	pub trait MultiOriginBatchApi<AccountId, Nonce, Call, PalletsOrigin, Extension, Balance>
	where
		AccountId: Codec,
		Nonce: Codec,
		Call: Codec,
		PalletsOrigin: Codec,
		Extension: Codec,
		Balance: Codec,
	{
		/// The extensions of the item pipeline `extension`, in metadata order, each with its
		/// encoded explicit and implicit data. `None` if the implicit data is unavailable.
		///
		/// See `Pallet::item_extensions`.
		fn item_extensions(extension: Extension) -> Option<Vec<ItemExtension>>;

		/// The payload the origin of the item at `index` of a batch authorizes, as its pipeline
		/// `extension` hands it to the authorizing extension at `authorizer`, the position of
		/// that extension in metadata order. The batch is described by its `mode`, its
		/// `submitter` with the `nonce` of the batch transaction and the calls and origins of
		/// all its `items`, in order. `None` if `authorizer` is out of range or the implicit
		/// data is unavailable.
		///
		/// See `Pallet::item_signing_payload`.
		fn item_signing_payload(
			mode: BatchMode,
			submitter: AccountId,
			nonce: Nonce,
			index: u32,
			items: Vec<(Call, PalletsOrigin)>,
			extension: Extension,
			authorizer: u32,
		) -> Option<Vec<u8>>;

		/// What the submitter of the batch transaction `uxt` of `len` bytes pays for: the weight
		/// and class of their share and its fee, before any refund for items which turn out to
		/// be free. `None` if `uxt` is not a batch.
		///
		/// See `MultiOriginBatch::query_share_info`.
		fn query_share_info(
			uxt: Block::Extrinsic,
			len: u32,
		) -> Option<RuntimeDispatchInfo<Balance>>;
	}
}
