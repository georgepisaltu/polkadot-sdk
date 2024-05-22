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

//! # Meta Tx or Meta Transaction pallet.
//!
//! The pallet provides a way to dispatch a transaction authorized by one party (the signer) and
//! executed by an untrusted third party (the relayer) that covers the transaction fees.
//!
//! ## Pallet API
//!
//! See the [`pallet`] module for more information about the interfaces this pallet exposes,
//! including its configuration trait, dispatchables, storage items, events and errors.
//!
//! ## Overview
//!
//! The pallet exposes a client level API which usually not meant to be used directly by the end
//! user. Meta transaction constructed with a wallet help will contain a target call, required
//! extensions and a signer signature then will be gossiped with the world and can be picked up by
//! anyone who is interested in relaying the transaction. The relayer will publish a regular
//! transaction with the [`dispatch`](`Pallet::dispatch`) call and the meta transaction as an
//! argument to execute the target call on behalf of the signer and cover the fees.
//!
//! The pallet exposes a client-level API, which is usually not meant to be used directly by the
//! end-user. A meta transaction constructed with a wallet's help will contain a target call,
//! required extensions, and a signer's signature. It will then be shared with the world and can
//! be picked up by anyone interested in relaying the transaction. The relayer will publish a
//! regular transaction with the [`dispatch`](`Pallet::dispatch`) call and the meta transaction as
//! an argument to execute the target call on behalf of the signer and cover the fees.
//!
//! ### Example
#![doc = docify::embed!("src/tests.rs", sign_and_execute_meta_tx)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub use pallet::*;

use frame_support::{
	dispatch::{extract_actual_weight, DispatchInfo, GetDispatchInfo, PostDispatchInfo},
	pallet_prelude::*,
	traits::OriginTrait,
};
use frame_system::pallet_prelude::*;
use sp_runtime::traits::{Dispatchable, IdentifyAccount, Verify, Zero};
use sp_std::prelude::*;

/// Meta Transaction type.
///
/// The data that is provided and signed by the signer and shared with the relayer.
#[derive(Encode, Decode, PartialEq, Eq, TypeInfo, Clone, RuntimeDebug)]
pub struct MetaTx<Address, Call, Hash, Nonce> {
	call: Box<Call>,
	signer: Address,
	nonce: Nonce,
	genesis_hash: Hash,
	spec_version: u32,
}

impl<Address, Call, Hash, Nonce> MetaTx<Address, Call, Hash, Nonce> {
	/// Create a new meta transaction.
	pub fn new(
		signer: Address,
		call: Call,
		nonce: Nonce,
		genesis_hash: Hash,
		spec_version: u32,
	) -> Self {
		Self { call: Box::new(call), signer, nonce, genesis_hash, spec_version }
	}

	pub fn deconstruct(self) -> (Box<Call>, Address) {
		(self.call, self.signer)
	}
}

/// Proof of the authenticity of the meta transaction.
// It could potentially be extended to support additional types of proofs, similar to the
// sp_runtime::generic::Preamble::Bare transaction type.
#[derive(Encode, Decode, PartialEq, Eq, TypeInfo, Clone, RuntimeDebug)]
pub enum Proof<Signature> {
	/// Signature of the meta transaction payload and the signer's address.
	Signed(Signature),
}

/// The [`MetaTx`] for the given config.
pub type MetaTxFor<T> = MetaTx<
	<<T as Config>::PublicKey as IdentifyAccount>::AccountId,
	<T as Config>::RuntimeCall,
	<T as frame_system::Config>::Hash,
	<T as frame_system::Config>::Nonce,
>;

/// The [`Proof`] for the given config.
pub type ProofFor<T> = Proof<<T as Config>::Signature>;

// TODO(quality of life): structs to aggregate
// - multisigner meta transactions
// - meta transactions coupled with a proof
// - multisigner meta transactions coupled with their associated proofs
// These would impl encode/decode and would help the clients integrate easier by calling
// `MultisignerMetaTxWithProofs::decode` on a byte array instead of
// `let (meta_txs, proofs): (Vec<MetaTx<...>>, Vec<Proof<...>>) = Decode::decode(&bytes[..]);`

#[frame_support::pallet(dev_mode)]
pub mod pallet {
	use super::*;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// The overarching call type.
		type RuntimeCall: Parameter
			+ GetDispatchInfo
			+ Dispatchable<
				Info = DispatchInfo,
				PostInfo = PostDispatchInfo,
				RuntimeOrigin = Self::RuntimeOrigin,
			> + IsType<<Self as frame_system::Config>::RuntimeCall>;
		/// Signature type for meta transactions.
		type Signature: Parameter + Verify<Signer = Self::PublicKey>;
		/// Public key type used for signature verification.
		type PublicKey: IdentifyAccount<AccountId = Self::AccountId>;
		/// Public key type used for signature verification.
		type MaxMultiSigners: Get<u32>;
		/// Maximum number of meta transactions allowed in a single dispatch with multiple signers.
		type MaxMultisignerTxCount: Get<u32>;
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Invalid proof (e.g. signature).
		BadProof,
		/// The meta transaction is not yet valid (e.g. nonce too high).
		Future,
		/// The meta transaction is outdated (e.g. nonce too low).
		Stale,
		/// The meta transactions's birth block is ancient.
		AncientBirthBlock,
		/// The meta transaction is invalid.
		Invalid,
		/// Maximum participant count in the meta transaction exceeded.
		TooManySigners,
		/// Account tries to run a call without paying for their nonce.
		NoNonce,
		/// Maximum transaction count in the multisigner meta transaction exceeded.
		TooManyTransactions,
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(crate) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A call was dispatched.
		Dispatched { result: DispatchResultWithPostInfo },
		// TODO: more (better) events.
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Dispatch a given meta transaction.
		///
		/// - `_origin`: Can be any kind of origin.
		/// - `meta_tx`: Meta Transaction with a target call to be dispatched.
		/// - `proof`: Signature of the meta transaction.
		#[pallet::call_index(0)]
		#[pallet::weight({
			let dispatch_info = meta_tx.call.get_dispatch_info();
			// TODO: plus T::WeightInfo::dispatch()
			(
				dispatch_info.weight,
				dispatch_info.class,
			)
		})]
		pub fn dispatch(
			_origin: OriginFor<T>,
			meta_tx: MetaTxFor<T>,
			proof: ProofFor<T>,
		) -> DispatchResultWithPostInfo {
			Self::verify_proof(&meta_tx, &proof)?;
			Self::validate_meta_tx(&meta_tx)?;
			let (call, caller) = meta_tx.deconstruct();
			let origin = T::RuntimeOrigin::signed(caller.clone());

			let res = call.dispatch(origin);

			frame_system::Pallet::<T>::inc_account_nonce(&caller);
			Self::deposit_event(Event::Dispatched { result: res });

			res
		}

		/// Dispatch multiple meta transactions.
		///
		/// - `_origin`: Can be any kind of origin.
		/// - `meta_txs`: Meta Transactions with target calls to be dispatched.
		/// - `proofs`: List of signatures from each of the participants in the batch of Meta
		///   Transactions, sorted in order of their public keys (account IDs) - sorted thing is
		///   TBD.
		#[pallet::call_index(1)]
		#[pallet::weight({
			let mut weight = Weight::zero();
			for meta_tx in meta_txs.iter() {
				let dispatch_info = meta_tx.call.get_dispatch_info();
				weight = weight.saturating_add(dispatch_info.weight);
			}
			// TODO: plus T::WeightInfo::dispatch_multisigner()
			weight
		})]
		pub fn dispatch_multisigner(
			_origin: OriginFor<T>,
			meta_txs: Vec<MetaTxFor<T>>,
			proofs: Vec<ProofFor<T>>,
		) -> DispatchResultWithPostInfo {
			ensure!(proofs.len() <= meta_txs.len(), Error::<T>::TooManySigners);
			ensure!(
				meta_txs.len() <= T::MaxMultisignerTxCount::get() as usize,
				Error::<T>::TooManyTransactions
			);
			let signers = Self::verify_multiproofs(&meta_txs[..], &proofs[..])?;

			let mut weight = Weight::zero();

			for meta_tx in meta_txs.into_iter() {
				Self::validate_meta_tx(&meta_tx)?;
				let (call, caller) = meta_tx.deconstruct();

				let info = call.get_dispatch_info();
				let origin = T::RuntimeOrigin::signed(caller);
				let result = call.dispatch(origin);
				weight = weight.saturating_add(extract_actual_weight(&result, &info));
				if let Err(_e) = result {
					return Ok(Some(weight).into())
				}
				Self::deposit_event(Event::Dispatched { result });
			}

			for signer in signers.iter() {
				frame_system::Pallet::<T>::inc_account_nonce(&signer);
			}

			Ok(Some(weight).into())
		}
	}

	impl<T: Config> Pallet<T> {
		// Verify the signature for a meta transaction.
		// The payload to be signed is the encoded byte array of `meta_tx`.
		fn verify_proof(meta_tx: &MetaTxFor<T>, proof: &ProofFor<T>) -> DispatchResult {
			match proof {
				Proof::Signed(signature) => {
					if meta_tx
						.using_encoded(|payload| signature.verify(&payload[..], &meta_tx.signer))
					{
						Ok(())
					} else {
						Err(Error::<T>::BadProof.into())
					}
				},
			}
		}

		// Verify the signatures for a multisigner (batch) meta transaction.
		// The payload to be signed is the encoded byte array of `(meta_txs, signers)`, where:
		// - `meta_txs` is the list of the meta transactions to be run, in order
		// - `signers` is a list of all signers' public keys (account IDs) that participate in this
		//   multisigner meta transaction, in the form of a `BoundedBTreeSet<T::AccountId,
		//   T::MaxMultiSigners>`
		//
		// The provided proofs must be in the same order as their respective signers in the original
		// `signers` list (TBD and this may change - this is done to avoid requiring a signer that
		// has multiple meta transactions in this call to have to provide multiple signatures, but
		// we may be able to nicely abstract this away in some runtime API call).
		fn verify_multiproofs(
			meta_txs: &[MetaTxFor<T>],
			proofs: &[ProofFor<T>],
		) -> Result<BoundedBTreeSet<T::AccountId, T::MaxMultiSigners>, DispatchError> {
			let mut signers: BoundedBTreeSet<T::AccountId, T::MaxMultiSigners> = Default::default();
			for meta_tx in meta_txs.iter() {
				signers
					.try_insert(meta_tx.signer.clone())
					.map_err(|_| Error::<T>::TooManySigners)?;
			}
			ensure!(signers.len() == proofs.len(), Error::<T>::Invalid);
			let payload = (meta_txs, &signers).encode();
			for (signer, proof) in signers.iter().zip(proofs.iter()) {
				match proof {
					Proof::Signed(signature) =>
						if !signature.verify(&payload[..], &signer) {
							return Err(Error::<T>::BadProof.into());
						},
				}
			}
			Ok(signers)
		}

		// Basic validation checks for a meta transaction:
		// - nonce
		// - spec version (inherently includes transaction version)
		// - genesis hash
		fn validate_meta_tx(meta_tx: &MetaTxFor<T>) -> DispatchResult {
			let account = frame_system::Account::<T>::get(&meta_tx.signer);
			ensure!(account.providers > 0 || account.sufficients > 0, Error::<T>::NoNonce);
			ensure!(account.nonce == meta_tx.nonce, Error::<T>::Stale);
			ensure!(
				frame_system::Pallet::<T>::runtime_version().spec_version == meta_tx.spec_version,
				Error::<T>::Invalid
			);
			ensure!(
				frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero()) ==
					meta_tx.genesis_hash,
				Error::<T>::Invalid
			);
			Ok(())
		}

		/// Helper function to create the payload to be signed by all parties for a multisigner meta
		/// transaction.
		pub fn create_multisigner_payload(meta_txs: &[MetaTxFor<T>]) -> Result<Vec<u8>, Error<T>> {
			let mut signers: BoundedBTreeSet<T::AccountId, T::MaxMultiSigners> = Default::default();
			for meta_tx in meta_txs.iter() {
				signers
					.try_insert(meta_tx.signer.clone())
					.map_err(|_| Error::<T>::TooManySigners)?;
			}
			Ok((meta_txs, &signers).encode())
		}
	}

	/// Implements [`From<TransactionValidityError>`] for [`Error`] by mapping the relevant error
	/// variants.
	impl<T> From<TransactionValidityError> for Error<T> {
		fn from(err: TransactionValidityError) -> Self {
			use TransactionValidityError::*;
			match err {
				Unknown(_) => Error::<T>::Invalid,
				Invalid(err) => match err {
					InvalidTransaction::BadProof => Error::<T>::BadProof,
					InvalidTransaction::Future => Error::<T>::Future,
					InvalidTransaction::Stale => Error::<T>::Stale,
					InvalidTransaction::AncientBirthBlock => Error::<T>::AncientBirthBlock,
					_ => Error::<T>::Invalid,
				},
			}
		}
	}
}
