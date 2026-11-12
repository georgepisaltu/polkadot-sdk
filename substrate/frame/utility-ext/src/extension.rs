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

//! The transaction extension refunding the submitter of a multi-origin batch for its free items.

use crate::{Config, Pallet, RefundableShare};
use codec::{Decode, DecodeWithMemTracking, Encode};
use core::marker::PhantomData;
use frame_support::{
	dispatch::{DispatchInfo, PostDispatchInfo},
	pallet_prelude::TransactionSource,
};
use scale_info::{StaticTypeInfo, TypeInfo};
use sp_runtime::{
	traits::{Implication, TransactionExtension, TransactionExtensionMetadata, ValidateResult},
	transaction_validity::TransactionValidityError,
	DispatchResult, Weight,
};

type RuntimeCallOf<T> = <T as frame_system::Config>::RuntimeCall;
type RuntimeOriginOf<T> = <T as frame_system::Config>::RuntimeOrigin;

/// Wraps the runtime's fee payment extension `S` so that it charges the submitter of a
/// multi-origin batch without the share of the items whose dispatch returned `Pays::No`: `S`
/// settles the fee as if the batch had used that much less weight and bytes, which
/// [`RefundableShare`] carries from the batch call to `post_dispatch`. The weight the rest of the
/// pipeline sees is unchanged, so the block accounts for the free items. Other transactions go
/// through to `S` untouched.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq)]
pub struct RefundFreeItems<T, S>(pub S, PhantomData<T>);

// Invisible from the outside, like the wrapped extension's metadata, identifier and implicit.
impl<T, S: StaticTypeInfo> TypeInfo for RefundFreeItems<T, S> {
	type Identity = S;
	fn type_info() -> scale_info::Type {
		S::type_info()
	}
}

impl<T, S: Encode> core::fmt::Debug for RefundFreeItems<T, S> {
	#[cfg(feature = "std")]
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "RefundFreeItems<{:?}>", self.0.encode())
	}
	#[cfg(not(feature = "std"))]
	fn fmt(&self, _: &mut core::fmt::Formatter) -> core::fmt::Result {
		Ok(())
	}
}

impl<T, S> From<S> for RefundFreeItems<T, S> {
	fn from(s: S) -> Self {
		Self(s, PhantomData)
	}
}

impl<T: Config + Send + Sync, S: TransactionExtension<RuntimeCallOf<T>>>
	TransactionExtension<RuntimeCallOf<T>> for RefundFreeItems<T, S>
{
	const IDENTIFIER: &'static str = S::IDENTIFIER;
	type Implicit = S::Implicit;
	type Val = S::Val;
	/// The wrapped extension's and whether the transaction is a batch.
	type Pre = (S::Pre, bool);

	fn metadata() -> alloc::vec::Vec<TransactionExtensionMetadata> {
		S::metadata()
	}

	fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
		self.0.implicit()
	}

	fn weight(&self, call: &RuntimeCallOf<T>) -> Weight {
		self.0.weight(call)
	}

	fn validate(
		&self,
		origin: RuntimeOriginOf<T>,
		call: &RuntimeCallOf<T>,
		info: &DispatchInfo,
		len: usize,
		self_implicit: Self::Implicit,
		inherited_implication: &impl Implication,
		source: TransactionSource,
	) -> ValidateResult<Self::Val, RuntimeCallOf<T>> {
		self.0
			.validate(origin, call, info, len, self_implicit, inherited_implication, source)
	}

	fn prepare(
		self,
		val: Self::Val,
		origin: &RuntimeOriginOf<T>,
		call: &RuntimeCallOf<T>,
		info: &DispatchInfo,
		len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		let batch = Pallet::<T>::is_batch(call);
		if batch {
			RefundableShare::<T>::kill();
		}
		Ok((self.0.prepare(val, origin, call, info, len)?, batch))
	}

	fn post_dispatch_details(
		(pre, batch): Self::Pre,
		info: &DispatchInfo,
		post_info: &PostDispatchInfo,
		len: usize,
		result: &DispatchResult,
	) -> Result<Weight, TransactionValidityError> {
		let (free_weight, free_len) = if batch {
			RefundableShare::<T>::take().unwrap_or_default()
		} else {
			Default::default()
		};
		let charged = PostDispatchInfo {
			actual_weight: Some(post_info.calc_actual_weight(info).saturating_sub(free_weight)),
			pays_fee: post_info.pays_fee,
		};
		let len = (len as u32).saturating_sub(free_len) as usize;
		S::post_dispatch_details(pre, info, &charged, len, result)
	}
}
