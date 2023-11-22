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

/// Shortcut for the result value of the `validate` function.
pub type ValidateResult<TE, Call> = Result<
	(ValidTransaction, <TE as TransactionExtension<Call>>::Val, OriginOf<Call>),
	TransactionValidityError,
>;

/// Shortcut for the result value of the `validate` function.
pub type SimpleValidateResult<TE, Call> = Result<
	(ValidTransaction, <TE as SimpleTransactionExtension<Call>>::Val, OriginOf<Call>),
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

/// Means by which a transaction may be extended. This type embodies both the data and the logic
/// that should be additionally associated with the transaction. It should be plain old data.
pub trait SimpleTransactionExtension<Call: Dispatchable>:
	Codec + Debug + Sync + Send + Clone + Eq + PartialEq + StaticTypeInfo
{
	/// Unique identifier of this signed extension.
	///
	/// This will be exposed in the metadata to identify the signed extension used
	/// in an extrinsic.
	const IDENTIFIER: &'static str;

	/// The type that encodes information that can be passed from validate to prepare.
	type Val: Default;

	/// The type that encodes information that can be passed from prepare to post-dispatch.
	type Pre: Default;

	/// Any additional data which was known at the time of transaction construction and
	/// can be useful in authenticating the transaction. This is determined dynamically in part
	/// from the on-chain environment using the `implied` function and not directly contained in
	/// the transction itself and therefore is considered "implicit".
	type Implicit: Encode + StaticTypeInfo + Default;

	/// Determine any additional data which was known at the time of transaction construction and
	/// can be useful in authenticating the transaction. The expected usage of this is to include
	/// in any data which is signed and verified as part of transactiob validation. Also perform
	/// any pre-signature-verification checks and return an error if needed.
	fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
		Ok(Default::default())
	}

	/// Validate a transaction for the transaction queue.
	///
	/// This function can be called frequently by the transaction queue to obtain transaction
	/// validity against current state. It should perform all checks that determine a valid
	/// transaction, that can pay for its execution and quickly eliminate ones that are stale or
	/// incorrect.
	fn validate(
		&self,
		origin: OriginOf<Call>,
		_call: &Call,
		_info: &DispatchInfoOf<Call>,
		_len: usize,
		_target: &[u8],
	) -> SimpleValidateResult<Self, Call> {
		Ok((Default::default(), Default::default(), origin))
	}

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
		_val: Self::Val,
		_origin: &OriginOf<Call>,
		_call: &Call,
		_info: &DispatchInfoOf<Call>,
		_len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		Ok(Default::default())
	}

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
}

/// Transform a `SimpleTransactionExtension` into a `TransactionExtension`.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct WithSimple<S>(S);
impl<Call: Dispatchable, S: SimpleTransactionExtension<Call>> TransactionExtension<Call>
	for WithSimple<S>
{
	const IDENTIFIER: &'static str = S::IDENTIFIER;
	type Val = S::Val;
	type Pre = S::Pre;
	type Implicit = S::Implicit;
	fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
		self.0.implicit()
	}
	fn validate(
		&self,
		origin: OriginOf<Call>,
		call: &Call,
		info: &DispatchInfoOf<Call>,
		len: usize,
		target: &[u8],
	) -> ValidateResult<Self, Call> {
		self.0.validate(origin, call, info, len, target)
	}
	fn prepare(
		self,
		val: Self::Val,
		origin: &OriginOf<Call>,
		call: &Call,
		info: &DispatchInfoOf<Call>,
		len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		self.0.prepare(val, origin, call, info, len)
	}
	fn post_dispatch(
		pre: Self::Pre,
		info: &DispatchInfoOf<Call>,
		post_info: &PostDispatchInfoOf<Call>,
		len: usize,
		result: &DispatchResult,
	) -> Result<(), TransactionValidityError> {
		S::post_dispatch(pre, info, post_info, len, result)
	}
	fn metadata() -> Vec<TransactionExtensionMetadata> {
		S::metadata()
	}
}
impl<S: TypeInfo> TypeInfo for WithSimple<S> {
	type Identity = S::Identity;
	fn type_info() -> Type {
		S::type_info()
	}
}

/// Single-function utility trait with a blanket impl over `TransactionExtension` in order to
/// provide transaction dispatching functionality. We avoid implementing this directly on the
/// trait since we never want it to be overriden by the trait implementation.
pub trait DispatchTransaction<Call: Dispatchable> {
	/// The origin type of the transaction.
	type Origin;
	/// The info type.
	type Info;
	/// The resultant type.
	type Result;
	/// The `Val` of the extension.
	type Val;
	/// The `Pre` of the extension.
	type Pre;
	/// Just validate a transaction.
	///
	/// The is basically the same as `validate`, except that there is no need to supply the
	/// bond data.
	fn validate_only(
		&self,
		origin: Self::Origin,
		call: &Call,
		info: &Self::Info,
		len: usize,
	) -> Result<(ValidTransaction, Self::Val, Self::Origin), TransactionValidityError>;
	/// Prepare and validate a transaction, ready for dispatch.
	fn validate_and_prepare(
		self,
		origin: Self::Origin,
		function: &Call,
		info: &Self::Info,
		len: usize,
	) -> Result<(Self::Pre, Self::Origin), TransactionValidityError>;
	/// Dispatch a transaction with the given base origin and call.
	fn dispatch_transaction(
		self,
		origin: Self::Origin,
		function: Call,
		info: &Self::Info,
		len: usize,
	) -> Self::Result;
}

impl<T: TransactionExtension<Call>, Call: Dispatchable> DispatchTransaction<Call> for T {
	type Origin = <Call as Dispatchable>::RuntimeOrigin;
	type Info = DispatchInfoOf<Call>;
	type Result = crate::ApplyExtrinsicResultWithInfo<PostDispatchInfoOf<Call>>;
	type Val = T::Val;
	type Pre = T::Pre;

	fn validate_only(
		&self,
		origin: Self::Origin,
		call: &Call,
		info: &DispatchInfoOf<Call>,
		len: usize,
	) -> Result<(ValidTransaction, T::Val, Self::Origin), TransactionValidityError> {
		let target = (self, self.implicit()?).encode();
		self.validate(origin, call, info, len, &target[..])
	}
	fn validate_and_prepare(
		self,
		origin: Self::Origin,
		call: &Call,
		info: &DispatchInfoOf<Call>,
		len: usize,
	) -> Result<(T::Pre, Self::Origin), TransactionValidityError> {
		let (_, val, origin) = self.validate_only(origin, call, info, len)?;
		let pre = self.prepare(val, &origin, &call, info, len)?;
		Ok((pre, origin))
	}
	fn dispatch_transaction(
		self,
		origin: <Call as Dispatchable>::RuntimeOrigin,
		call: Call,
		info: &DispatchInfoOf<Call>,
		len: usize,
	) -> Self::Result {
		let (pre, origin) = self.validate_and_prepare(origin, &call, info, len)?;
		let res = call.dispatch(origin);
		let post_info = match res {
			Ok(info) => info,
			Err(err) => err.post_info,
		};
		let pd_res = res.map(|_| ()).map_err(|e| e.error);
		T::post_dispatch(pre, info, &post_info, len, &pd_res)?;
		Ok(res)
	}
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

/// Adapter to use a `SignedExtension` in the place of a `TransactionExtension`.
#[derive(TypeInfo, Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
//#[deprecated = "Convert your SignedExtension to a TransactionExtension."]
pub struct AsTransactionExtension<SE: SignedExtension>(pub SE);

impl<SE: SignedExtension + Default> Default for AsTransactionExtension<SE> {
	fn default() -> Self {
		Self(SE::default())
	}
}

impl<SE: SignedExtension> From<SE> for AsTransactionExtension<SE> {
	fn from(value: SE) -> Self {
		Self(value)
	}
}

impl<SE: SignedExtension> TransactionExtension<SE::Call> for AsTransactionExtension<SE>
where
	<SE::Call as Dispatchable>::RuntimeOrigin: CloneSystemOriginSigner<SE::AccountId> + Clone,
{
	const IDENTIFIER: &'static str = SE::IDENTIFIER;
	type Val = ();
	type Pre = SE::Pre;
	type Implicit = SE::AdditionalSigned;

	fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
		self.0.additional_signed()
	}

	fn validate(
		&self,
		origin: <SE::Call as Dispatchable>::RuntimeOrigin,
		call: &SE::Call,
		info: &DispatchInfoOf<SE::Call>,
		len: usize,
		_implicit: &[u8],
	) -> Result<
		(ValidTransaction, (), <SE::Call as Dispatchable>::RuntimeOrigin),
		TransactionValidityError,
	> {
		let who = origin.clone_system_origin_signer().ok_or(InvalidTransaction::BadSigner)?;
		Ok((self.0.validate(&who, call, info, len)?, (), origin))
	}

	fn prepare(
		self,
		_: (),
		origin: &<SE::Call as Dispatchable>::RuntimeOrigin,
		call: &SE::Call,
		info: &DispatchInfoOf<SE::Call>,
		len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		let who = origin.clone_system_origin_signer().ok_or(InvalidTransaction::BadSigner)?;
		self.0.pre_dispatch(&who, call, info, len)
	}

	fn post_dispatch(
		pre: Self::Pre,
		info: &DispatchInfoOf<SE::Call>,
		post_info: &PostDispatchInfoOf<SE::Call>,
		len: usize,
		result: &DispatchResult,
	) -> Result<(), TransactionValidityError> {
		SE::post_dispatch(Some(pre), info, post_info, len, result)
	}

	fn validate_bare_compat(
		call: &SE::Call,
		info: &DispatchInfoOf<SE::Call>,
		len: usize,
	) -> TransactionValidity {
		#[allow(deprecated)]
		SE::validate_unsigned(call, info, len)
	}

	fn pre_dispatch_bare_compat(
		call: &SE::Call,
		info: &DispatchInfoOf<SE::Call>,
		len: usize,
	) -> Result<(), TransactionValidityError> {
		#[allow(deprecated)]
		SE::pre_dispatch_unsigned(call, info, len)
	}

	fn post_dispatch_bare_compat(
		info: &DispatchInfoOf<SE::Call>,
		post_info: &PostDispatchInfoOf<SE::Call>,
		len: usize,
		result: &DispatchResult,
	) -> Result<(), TransactionValidityError> {
		SE::post_dispatch(None, info, post_info, len, result)
	}
}
