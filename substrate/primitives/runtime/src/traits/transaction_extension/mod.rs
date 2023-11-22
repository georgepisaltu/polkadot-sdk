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

//! The transaction extension trait.

use crate::{
	scale_info::{MetaType, StaticTypeInfo, TypeInfo},
	traits::SignedExtension,
	transaction_validity::{
		InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransaction,
	},
	DispatchResult,
};
use codec::{Codec, Decode, Encode};
use impl_trait_for_tuples::impl_for_tuples;
use scale_info::Type;
use sp_core::{self, RuntimeDebug};
#[doc(hidden)]
pub use sp_std::marker::PhantomData;
use sp_std::{self, fmt::Debug, prelude::*};

use super::{CloneSystemOriginSigner, DispatchInfoOf, Dispatchable, OriginOf, PostDispatchInfoOf};

mod as_transaction_extension;
mod dispatch_transaction;
mod simple_transaction_extension;
pub use as_transaction_extension::AsTransactionExtension;
pub use dispatch_transaction::DispatchTransaction;
pub use simple_transaction_extension::{SimpleTransactionExtension, WithSimple};

/// Shortcut for the result value of the `validate` function.
pub type ValidateResult<TE, Call> = Result<
	(ValidTransaction, <TE as TransactionExtension<Call>>::Val, OriginOf<Call>),
	TransactionValidityError,
>;

/// Means by which a transaction may be extended. This type embodies both the data and the logic
/// that should be additionally associated with the transaction. It should be plain old data.
pub trait TransactionExtension<Call: Dispatchable>:
	Codec + Debug + Sync + Send + Clone + Eq + PartialEq + StaticTypeInfo
{
	/// Unique identifier of this signed extension.
	///
	/// This will be exposed in the metadata to identify the signed extension used
	/// in an extrinsic.
	const IDENTIFIER: &'static str;

	/// The type that encodes information that can be passed from validate to prepare.
	type Val;

	/// The type that encodes information that can be passed from prepare to post-dispatch.
	type Pre;

	/// Any additional data which was known at the time of transaction construction and
	/// can be useful in authenticating the transaction. This is determined dynamically in part
	/// from the on-chain environment using the `implied` function and not directly contained in
	/// the transction itself and therefore is considered "implicit".
	type Implicit: Encode + StaticTypeInfo;

	/// Determine any additional data which was known at the time of transaction construction and
	/// can be useful in authenticating the transaction. The expected usage of this is to include
	/// in any data which is signed and verified as part of transactiob validation. Also perform
	/// any pre-signature-verification checks and return an error if needed.
	fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError>;

	/// Validate a transaction for the transaction queue.
	///
	/// This function can be called frequently by the transaction queue to obtain transaction
	/// validity against current state. It should perform all checks that determine a valid
	/// transaction, that can pay for its execution and quickly eliminate ones that are stale or
	/// incorrect.
	fn validate(
		&self,
		origin: OriginOf<Call>,
		call: &Call,
		info: &DispatchInfoOf<Call>,
		len: usize,
		target: &[u8],
	) -> ValidateResult<Self, Call>;

	/// Do any pre-flight stuff for a transaction after validation.
	///
	/// This is for actions which do not happen in the transaction queue but only immediately prior
	/// to the point of dispatch on-chain. This should not return an error, since errors
	/// should already have been identified during the [validate] call. If an error is returned,
	/// the transaction will be considered invalid.
	///
	/// Unlike `validate`, this function may consume `self`.
	///
	/// Checks made in validation need not be repeated here.
	fn prepare(
		self,
		val: Self::Val,
		origin: &OriginOf<Call>,
		call: &Call,
		info: &DispatchInfoOf<Call>,
		len: usize,
	) -> Result<Self::Pre, TransactionValidityError>;

	/// Do any post-flight stuff for an extrinsic.
	///
	/// `_pre` contains the output of `prepare`.
	///
	/// This gets given the `DispatchResult` `_result` from the extrinsic and can, if desired,
	/// introduce a `TransactionValidityError`, causing the block to become invalid for including
	/// it.
	///
	/// WARNING: It is dangerous to return an error here. To do so will fundamentally invalidate the
	/// transaction and any block that it is included in, causing the block author to not be
	/// compensated for their work in validating the transaction or producing the block so far.
	///
	/// It can only be used safely when you *know* that the extrinsic is one that can only be
	/// introduced by the current block author; generally this implies that it is an inherent and
	/// will come from either an offchain-worker or via `InherentData`.
	fn post_dispatch(
		_pre: Self::Pre,
		_info: &DispatchInfoOf<Call>,
		_post_info: &PostDispatchInfoOf<Call>,
		_len: usize,
		_result: &DispatchResult,
	) -> Result<(), TransactionValidityError> {
		Ok(())
	}

	/// Returns the metadata for this extension.
	///
	/// As a [`TransactionExtension`] can be a tuple of [`TransactionExtension`]s we need to return
	/// a `Vec` that holds the metadata of each one. Each individual `TransactionExtension` must
	/// return *exactly* one [`TransactionExtensionMetadata`].
	///
	/// This method provides a default implementation that returns a vec containing a single
	/// [`TransactionExtensionMetadata`].
	fn metadata() -> Vec<TransactionExtensionMetadata> {
		sp_std::vec![TransactionExtensionMetadata {
			identifier: Self::IDENTIFIER,
			ty: scale_info::meta_type::<Self>(),
			// TODO: Metadata-v16: Rename to "implicit"
			additional_signed: scale_info::meta_type::<Self::Implicit>()
		}]
	}

	/// Compatibility function for supporting the `SignedExtension::validate_unsigned` function.
	///
	/// DO NOT USE! THIS MAY BE REMOVED AT ANY TIME!
	#[deprecated = "Only for compatibility. DO NOT USE."]
	fn validate_bare_compat(
		_call: &Call,
		_info: &DispatchInfoOf<Call>,
		_len: usize,
	) -> TransactionValidity {
		Ok(ValidTransaction::default())
	}

	/// Compatibility function for supporting the `SignedExtension::pre_dispatch_unsigned` function.
	///
	/// DO NOT USE! THIS MAY BE REMOVED AT ANY TIME!
	#[deprecated = "Only for compatibility. DO NOT USE."]
	fn pre_dispatch_bare_compat(
		_call: &Call,
		_info: &DispatchInfoOf<Call>,
		_len: usize,
	) -> Result<(), TransactionValidityError> {
		Ok(())
	}

	/// Compatibility function for supporting the `SignedExtension::post_dispatch` function where
	/// `pre` is `None`.
	///
	/// DO NOT USE! THIS MAY BE REMOVED AT ANY TIME!
	#[deprecated = "Only for compatibility. DO NOT USE."]
	fn post_dispatch_bare_compat(
		_info: &DispatchInfoOf<Call>,
		_post_info: &PostDispatchInfoOf<Call>,
		_len: usize,
		_result: &DispatchResult,
	) -> Result<(), TransactionValidityError> {
		Ok(())
	}
}

/// Implict
#[macro_export]
macro_rules! impl_tx_ext_default {
	($call:ty ; implicit $( $rest:tt )*) => {
		fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
			Ok(Default::default())
		}
		impl_tx_ext_default!{$call ; $( $rest )*}
	};
	($call:ty ; validate $( $rest:tt )*) => {
		fn validate(
			&self,
			origin: sp_runtime::traits::OriginOf<$call>,
			_call: &$call,
			_info: &DispatchInfoOf<$call>,
			_len: usize,
			_target: &[u8],
		) -> sp_runtime::traits::ValidateResult<Self, $call> {
			Ok((Default::default(), Default::default(), origin))
		}
		impl_tx_ext_default!{$call ; $( $rest )*}
	};
	($call:ty ; prepare $( $rest:tt )*) => {
		fn prepare(
			self,
			_val: Self::Val,
			_origin: &sp_runtime::traits::OriginOf<$call>,
			_call: &$call,
			_info: &DispatchInfoOf<$call>,
			_len: usize,
		) -> Result<Self::Pre, TransactionValidityError> {
			Ok(Default::default())
		}
		impl_tx_ext_default!{$call ; $( $rest )*}
	};
	($call:ty ;) => {};
}

/// Information about a [`TransactionExtension`] for the runtime metadata.
pub struct TransactionExtensionMetadata {
	/// The unique identifier of the [`TransactionExtension`].
	pub identifier: &'static str,
	/// The type of the [`TransactionExtension`].
	pub ty: MetaType,
	/// The type of the [`TransactionExtension`] additional signed data for the payload.
	// TODO: Rename "implicit"
	pub additional_signed: MetaType,
}

#[impl_for_tuples(1, 12)]
impl<Call: Dispatchable> TransactionExtension<Call> for Tuple {
	for_tuples!( where #( Tuple: TransactionExtension<Call> )* );
	const IDENTIFIER: &'static str = "Use `metadata()`!";
	for_tuples!( type Val = ( #( Tuple::Val ),* ); );
	for_tuples!( type Pre = ( #( Tuple::Pre ),* ); );
	for_tuples!( type Implicit = ( #( Tuple::Implicit ),* ); );
	fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
		Ok(for_tuples!( ( #( Tuple.implicit()? ),* ) ))
	}

	fn validate(
		&self,
		origin: <Call as Dispatchable>::RuntimeOrigin,
		call: &Call,
		info: &DispatchInfoOf<Call>,
		len: usize,
		implicit: &[u8],
	) -> Result<
		(ValidTransaction, Self::Val, <Call as Dispatchable>::RuntimeOrigin),
		TransactionValidityError,
	> {
		let mut aggregated_valid = ValidTransaction::default();
		let mut aggregated_origin = origin;
		let aggregated_val = for_tuples!( ( #( {
			let (valid, val, origin) = Tuple.validate(aggregated_origin, call, info, len, implicit)?;
			aggregated_origin = origin;
			aggregated_valid = aggregated_valid.combine_with(valid);
			val
		} ),* ) );
		Ok((aggregated_valid, aggregated_val, aggregated_origin))
	}

	fn prepare(
		self,
		val: Self::Val,
		origin: &<Call as Dispatchable>::RuntimeOrigin,
		call: &Call,
		info: &DispatchInfoOf<Call>,
		len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		Ok(for_tuples!( ( #(
			Tuple::prepare(self.Tuple, val.Tuple, origin, call, info, len)?
		),* ) ))
	}

	fn post_dispatch(
		pre: Self::Pre,
		info: &DispatchInfoOf<Call>,
		post_info: &PostDispatchInfoOf<Call>,
		len: usize,
		result: &DispatchResult,
	) -> Result<(), TransactionValidityError> {
		for_tuples!( #( Tuple::post_dispatch(pre.Tuple, info, post_info, len, result)?; )* );
		Ok(())
	}

	fn metadata() -> Vec<TransactionExtensionMetadata> {
		let mut ids = Vec::new();
		for_tuples!( #( ids.extend(Tuple::metadata()); )* );
		ids
	}
}

impl<Call: Dispatchable> TransactionExtension<Call> for () {
	const IDENTIFIER: &'static str = "UnitTransactionExtension";
	type Val = ();
	type Pre = ();
	type Implicit = ();
	fn implicit(&self) -> sp_std::result::Result<Self::Implicit, TransactionValidityError> {
		Ok(())
	}
	fn validate(
		&self,
		origin: <Call as Dispatchable>::RuntimeOrigin,
		_call: &Call,
		_info: &DispatchInfoOf<Call>,
		_len: usize,
		_implicit: &[u8],
	) -> Result<
		(ValidTransaction, (), <Call as Dispatchable>::RuntimeOrigin),
		TransactionValidityError,
	> {
		Ok((ValidTransaction::default(), (), origin))
	}
	fn prepare(
		self,
		_val: (),
		_origin: &<Call as Dispatchable>::RuntimeOrigin,
		_call: &Call,
		_info: &DispatchInfoOf<Call>,
		_len: usize,
	) -> Result<(), TransactionValidityError> {
		Ok(())
	}
}
