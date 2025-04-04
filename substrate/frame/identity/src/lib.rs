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

//! # Identity Pallet
//!
//! - [`Config`]
//! - [`Call`]
//!
//! ## Overview
//!
//! A federated naming system, allowing for multiple registrars to be added from a specified origin.
//! Registrars can set a fee to provide identity-verification service. Anyone can put forth a
//! proposed identity for a fixed deposit and ask for review by any number of registrars (paying
//! each of their fees). Registrar judgements are given as an `enum`, allowing for sophisticated,
//! multi-tier opinions.
//!
//! Some judgements are identified as *sticky*, which means they cannot be removed except by
//! complete removal of the identity, or by the registrar. Judgements are allowed to represent a
//! portion of funds that have been reserved for the registrar.
//!
//! A super-user can remove accounts and in doing so, slash the deposit.
//!
//! All accounts may also have a limited number of sub-accounts which may be specified by the owner;
//! by definition, these have equivalent ownership and each has an individual name.
//!
//! The number of registrars should be limited, and the deposit made sufficiently large, to ensure
//! no state-bloat attack is viable.
//!
//! ### Usernames
//!
//! The pallet provides functionality for username authorities to issue usernames, which are
//! independent of the identity information functionality; an account can set:
//! - an identity without setting a username
//! - a username without setting an identity
//! - an identity and a username
//!
//! The username functionality implemented in this pallet is meant to be a user friendly lookup of
//! accounts. There are mappings in both directions, "account -> username" and "username ->
//! account".
//!
//! Usernames are granted by authorities and grouped by suffix, with each suffix being administered
//! by one authority. To grant a username, a username authority can either:
//! - be given an allocation by governance of a specific amount of usernames to issue for free,
//!   without any deposit associated with storage costs;
//! - put up a deposit for each username it issues (usually a subsidized, reduced deposit, relative
//!   to other deposits in the system)
//!
//! Users can have multiple usernames that map to the same `AccountId`, however one `AccountId` can
//! only map to a single username, known as the _primary_. This primary username will be the result
//! of a lookup in the [UsernameOf] map for any given account.
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! #### For account-based users
//! * `set_identity` - Set the associated identity of an account; a small deposit is reserved if not
//!   already taken.
//! * `clear_identity` - Remove an account's associated identity; the deposit is returned.
//! * `request_judgement` - Request a judgement from a registrar, paying a fee.
//! * `cancel_request` - Cancel the previous request for a judgement.
//! * `accept_username` - Accept a username issued by a username authority.
//! * `set_primary_username` - Set a given username as an account's primary.
//!
//! #### For account-based users with Sub-Identities
//! * `set_subs` - Set the sub-accounts of an identity.
//! * `add_sub` - Add a sub-identity to an identity.
//! * `remove_sub` - Remove a sub-identity of an identity.
//! * `rename_sub` - Rename a sub-identity of an identity.
//! * `quit_sub` - Remove a sub-identity of an identity (called by the sub-identity).
//!
//! #### For People, i.e. users who have proven their personhood
//! * `set_personal_identity` - Sets the username and on-chain account for a person.
//! * `submit_personal_credential_evidence` - Open a case for an oracle to judge a social credential
//!   of a person.
//! * `clear_personal_identity` - Clear a person's username and personal identity information.
//!
//! #### For Registrars
//! * `set_fee` - Set the fee required to be paid for a judgement to be given by the registrar.
//! * `set_fields` - Set the fields that a registrar cares about in their judgements.
//! * `provide_judgement` - Provide a judgement to an identity.
//!
//! #### For Username Authorities
//! * `set_username_for` - Set a username for a given account. The account must approve it.
//! * `unbind_username` - Start the grace period for a username.
//!
//! #### For Superusers
//! * `add_registrar` - Add a new registrar to the system.
//! * `kill_identity` - Forcibly remove the associated identity; the deposit is lost.
//! * `add_username_authority` - Add an account with the ability to issue usernames.
//! * `remove_username_authority` - Remove an account with the ability to issue usernames.
//! * `kill_username` - Forcibly remove a username.
//! * `personal_credential_judged` - Callback for the oracle to enforce the judgement of a social
//!   credential.
//!
//! #### For anyone
//! * `remove_expired_approval` - Remove a username that was issued but never accepted.
//! * `remove_username` - Remove a username after its grace period has ended.
//!
//! [`Call`]: ./enum.Call.html
//! [`Config`]: ./trait.Config.html

#![cfg_attr(not(feature = "std"), no_std)]

mod benchmarking;
pub mod legacy;
pub mod migration;
#[cfg(test)]
mod tests;
pub mod types;
pub mod weights;

extern crate alloc;

use crate::types::{
	AuthorityProperties, Data, IdentityInformationProvider, Judgement, PersonalIdentity, Provider,
	RegistrarIndex, RegistrarInfo, Registration, Suffix, Username, UsernameInformation,
	UsernameReport,
};
use alloc::{boxed::Box, vec::Vec};
use codec::Encode;
use core::cmp::Ordering;
use frame_support::{
	ensure,
	pallet_prelude::{DispatchError, DispatchResult},
	traits::{
		reality::{
			identity::Social, Alias, Callback, Context, Data as IdentityData,
			Judgement as OracleJudgement, JudgementContext, Statement, StatementOracle, Truth,
		},
		BalanceStatus, Currency, Defensive, EnsureOriginWithArg, ExistenceRequirement, Get,
		OnUnbalanced, ReservableCurrency, StorageVersion, WithdrawReasons,
	},
	BoundedVec,
};
use frame_system::pallet_prelude::*;
pub use pallet::*;
use sp_runtime::traits::{
	AppendZerosInput, Hash, IdentifyAccount, Saturating, StaticLookup, Verify, Zero,
};
pub use weights::WeightInfo;

type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;
type NegativeImbalanceOf<T> = <<T as Config>::Currency as Currency<
	<T as frame_system::Config>::AccountId,
>>::NegativeImbalance;
type AccountIdLookupOf<T> = <<T as frame_system::Config>::Lookup as StaticLookup>::Source;
pub type OracleTicketOf<T> =
	<<T as Config>::Oracle as StatementOracle<<T as frame_system::Config>::RuntimeCall>>::Ticket;
type ProviderOf<T> = Provider<BalanceOf<T>>;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;

	pub const IDENTITY_CONTEXT: Context = *b"pop:polkadot.network/identity   ";

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// The currency trait.
		type Currency: ReservableCurrency<Self::AccountId>;

		/// The amount held on deposit for a registered identity.
		#[pallet::constant]
		type BasicDeposit: Get<BalanceOf<Self>>;

		/// The amount held on deposit per encoded byte for a registered identity.
		#[pallet::constant]
		type ByteDeposit: Get<BalanceOf<Self>>;

		/// The amount held on deposit per registered username. This value should change only in
		/// runtime upgrades with proper migration of existing deposits.
		#[pallet::constant]
		type UsernameDeposit: Get<BalanceOf<Self>>;

		/// The amount held on deposit for a registered subaccount. This should account for the fact
		/// that one storage item's value will increase by the size of an account ID, and there will
		/// be another trie item whose value is the size of an account ID plus 32 bytes.
		#[pallet::constant]
		type SubAccountDeposit: Get<BalanceOf<Self>>;

		/// The amount held on deposit per reported username.
		#[pallet::constant]
		type UsernameReportDeposit: Get<BalanceOf<Self>>;

		/// The maximum number of sub-accounts allowed per identified account.
		#[pallet::constant]
		type MaxSubAccounts: Get<u32>;

		/// The number of blocks that have to pass between the last time a given username was
		/// reported and now in order to be able to report it again. In other words, it represents
		/// the username validity safety period.
		#[pallet::constant]
		type UsernameReportTimeout: Get<BlockNumberFor<Self>>;

		/// Structure holding information about an identity.
		type IdentityInformation: IdentityInformationProvider;

		/// Maximum number of registrars allowed in the system. Needed to bound the complexity
		/// of, e.g., updating judgements.
		#[pallet::constant]
		type MaxRegistrars: Get<u32>;

		/// Maximum number of judgements per personal identity allowed in the system.
		#[pallet::constant]
		type MaxJudgements: Get<u32>;

		/// What to do with slashed funds.
		type Slashed: OnUnbalanced<NegativeImbalanceOf<Self>>;

		/// The origin which may forcibly set or remove a name. Root can always do this.
		type ForceOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// The origin which may add or remove registrars. Root can always do this.
		type RegistrarOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Signature type for pre-authorizing usernames off-chain.
		///
		/// Can verify whether an `Self::SigningPublicKey` created a signature.
		type OffchainSignature: Verify<Signer = Self::SigningPublicKey> + Parameter;

		/// Public key that corresponds to an on-chain `Self::AccountId`.
		type SigningPublicKey: IdentifyAccount<AccountId = Self::AccountId>;

		/// The origin which may add or remove username authorities. Root can always do this.
		type UsernameAuthorityOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// The number of blocks within which a username grant must be accepted.
		#[pallet::constant]
		type PendingUsernameExpiration: Get<BlockNumberFor<Self>>;

		/// The number of blocks that must pass to enable the permanent deletion of a username by
		/// its respective authority.
		#[pallet::constant]
		type UsernameGracePeriod: Get<BlockNumberFor<Self>>;

		/// The maximum length of a suffix.
		#[pallet::constant]
		type MaxSuffixLength: Get<u32>;

		/// The maximum length of a username, including its suffix and any system-added delimiters.
		#[pallet::constant]
		type MaxUsernameLength: Get<u32>;

		/// The minimum length of a username or suffix.
		#[pallet::constant]
		type MinUsernameLength: Get<u32>;

		/// Oracle used to:
		/// - determine whether the evidence supplied of establishing an identity is
		/// real or not,
		/// - determine whether a given username is valid or not.
		type Oracle: StatementOracle<Self::RuntimeCall>;

		/// How to recognise an origin representing a person.
		type EnsurePerson: EnsureOriginWithArg<OriginFor<Self>, Context, Success = Alias>;

		/// The fee that a person must pay through their associated on-chain account in order to
		/// remove their identity.
		#[pallet::constant]
		type CredentialRemovalPenalty: Get<BalanceOf<Self>>;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T>(_);

	/// Information that is pertinent to identify the entity behind an account. First item is the
	/// registration, second is the account's primary username.
	///
	/// TWOX-NOTE: OK ― `AccountId` is a secure hash.
	#[pallet::storage]
	pub type IdentityOf<T: Config> = StorageMap<
		_,
		Twox64Concat,
		T::AccountId,
		Registration<BalanceOf<T>, T::MaxRegistrars, T::IdentityInformation>,
		OptionQuery,
	>;

	/// Identifies the primary username of an account.
	#[pallet::storage]
	pub type UsernameOf<T: Config> =
		StorageMap<_, Twox64Concat, T::AccountId, Username<T>, OptionQuery>;

	/// The super-identity of an alternative "sub" identity together with its name, within that
	/// context. If the account is not some other account's sub-identity, then just `None`.
	#[pallet::storage]
	pub type SuperOf<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, (T::AccountId, Data), OptionQuery>;

	/// Alternative "sub" identities of this account.
	///
	/// The first item is the deposit, the second is a vector of the accounts.
	///
	/// TWOX-NOTE: OK ― `AccountId` is a secure hash.
	#[pallet::storage]
	pub type SubsOf<T: Config> = StorageMap<
		_,
		Twox64Concat,
		T::AccountId,
		(BalanceOf<T>, BoundedVec<T::AccountId, T::MaxSubAccounts>),
		ValueQuery,
	>;

	/// The set of registrars. Not expected to get very big as can only be added through a
	/// special origin (likely a council motion).
	///
	/// The index into this can be cast to `RegistrarIndex` to get a valid value.
	#[pallet::storage]
	pub type Registrars<T: Config> = StorageValue<
		_,
		BoundedVec<
			Option<
				RegistrarInfo<
					BalanceOf<T>,
					T::AccountId,
					<T::IdentityInformation as IdentityInformationProvider>::FieldsIdentifier,
				>,
			>,
			T::MaxRegistrars,
		>,
		ValueQuery,
	>;

	/// A map of the accounts who are authorized to grant usernames.
	#[pallet::storage]
	pub type AuthorityOf<T: Config> =
		StorageMap<_, Twox64Concat, Suffix<T>, AuthorityProperties<T::AccountId>, OptionQuery>;

	/// Reverse lookup from `username` to the `AccountId` that has registered it and the provider of
	/// the username. The `owner` value should be a key in the `UsernameOf` map, but it may not if
	/// the user has cleared their username or it has been removed.
	///
	/// Multiple usernames may map to the same `AccountId`, but `UsernameOf` will only map to one
	/// primary username.
	#[pallet::storage]
	pub type UsernameInfoOf<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		Username<T>,
		UsernameInformation<T::AccountId, BalanceOf<T>>,
		OptionQuery,
	>;

	/// Usernames that an authority has granted, but that the account controller has not confirmed
	/// that they want it.
	///
	/// Used primarily in cases where the `AccountId` cannot provide a signature
	/// because they are a pure proxy, multisig, etc. In order to confirm it, they should call
	/// [accept_username](`Call::accept_username`).
	///
	/// First tuple item is the account and second is the acceptance deadline.
	#[pallet::storage]
	#[pallet::getter(fn preapproved_usernames)]
	pub type PendingUsernames<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		Username<T>,
		(T::AccountId, BlockNumberFor<T>, ProviderOf<T>),
		OptionQuery,
	>;

	/// Usernames for which the authority that granted them has started the removal process by
	/// unbinding them. Each unbinding username maps to its grace period expiry, which is the first
	/// block in which the username could be deleted through a
	/// [remove_username](`Call::remove_username`) call.
	#[pallet::storage]
	pub type UnbindingUsernames<T: Config> =
		StorageMap<_, Blake2_128Concat, Username<T>, BlockNumberFor<T>, OptionQuery>;

	/// The metadata associated with a person through their contextual alias for the purposes of
	/// registering identity information.
	#[pallet::storage]
	pub type PersonIdentities<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		Alias,
		PersonalIdentity<T::AccountId, OracleTicketOf<T>, T::MaxJudgements, BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// Reverse lookup of accounts controlled by a person through a contextual alias. All people
	/// that registered an identity must also associate an on-chain account to it.
	#[pallet::storage]
	pub type AccountToAlias<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, Alias, OptionQuery>;

	/// Stores pending reports of usernames.
	#[pallet::storage]
	pub type PendingUsernameReports<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		Alias,
		UsernameReport<T::AccountId, Username<T>, OracleTicketOf<T>>,
		OptionQuery,
	>;

	#[pallet::error]
	pub enum Error<T> {
		/// Too many subs-accounts.
		TooManySubAccounts,
		/// No alias found for an account.
		NoAlias,
		/// Account isn't found.
		NotFound,
		/// Account isn't named.
		NotNamed,
		/// Empty index.
		EmptyIndex,
		/// Fee is changed.
		FeeChanged,
		/// No identity found.
		NoIdentity,
		/// Sticky judgement.
		StickyJudgement,
		/// Judgement given.
		JudgementGiven,
		/// Invalid judgement.
		InvalidJudgement,
		/// The index is invalid.
		InvalidIndex,
		/// The target is invalid.
		InvalidTarget,
		/// Maximum amount of registrars reached. Cannot add any more.
		TooManyRegistrars,
		/// Account ID is already named.
		AlreadyClaimed,
		/// Username has already been reported.
		AlreadyReported,
		/// Sender is not a sub-account.
		NotSub,
		/// Sub-account isn't owned by sender.
		NotOwned,
		/// The provided judgement was for a different identity.
		JudgementForDifferentIdentity,
		/// Error that occurs when there is an issue paying for judgement.
		JudgementPaymentFailed,
		/// The provided suffix is too long.
		InvalidSuffix,
		/// The sender does not have permission to issue a username.
		NotUsernameAuthority,
		/// The authority cannot allocate any more usernames.
		NoAllocation,
		/// The signature on a username was not valid.
		InvalidSignature,
		/// Setting this username requires a signature, but none was provided.
		RequiresSignature,
		/// The username does not meet the requirements.
		InvalidUsername,
		/// The username is already taken.
		UsernameTaken,
		/// The requested username does not exist.
		NoUsername,
		/// The reported username was not provided by the system.
		NotSystemProvidedUsername,
		/// The username cannot be forcefully removed because it can still be accepted.
		NotExpired,
		/// The username cannot be removed because it's still in the grace period.
		TooEarly,
		/// The username cannot be removed because it is not unbinding.
		NotUnbinding,
		/// The username cannot be unbound because it is already unbinding.
		AlreadyUnbinding,
		/// The action cannot be performed because of insufficient privileges (e.g. authority
		/// trying to unbind a username provided by the system).
		InsufficientPrivileges,
		/// The context in which the alias was used is not supported.
		BadContext,
		/// No associated request for the judgement received.
		UnexpectedJudgement,
		/// The social credential is not supported by the configured identity information provider.
		NotSupported,
		/// The person is banned and cannot perform the operation.
		Banned,
		/// The person already has a personal identity associated with their alias.
		AlreadyRegistered,
		/// The list of judgements ongoing on a personal identity is full.
		JudgementListFull,
		/// The username has been reported too recently.
		LastUsernameReportTooRecent,
		/// The username has been reported and is undergoing validity judgement.
		UsernameJudgementOngoing,
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A name was set or reset (which will remove all judgements).
		IdentitySet { who: T::AccountId },
		/// A name was cleared, and the given balance returned.
		IdentityCleared { who: T::AccountId, deposit: BalanceOf<T> },
		/// A name was removed and the given balance slashed.
		IdentityKilled { who: T::AccountId, deposit: BalanceOf<T> },
		/// A judgement was asked from a registrar.
		JudgementRequested { who: T::AccountId, registrar_index: RegistrarIndex },
		/// A judgement request was retracted.
		JudgementUnrequested { who: T::AccountId, registrar_index: RegistrarIndex },
		/// A judgement was given by a registrar.
		JudgementGiven { target: T::AccountId, registrar_index: RegistrarIndex },
		/// A registrar was added.
		RegistrarAdded { registrar_index: RegistrarIndex },
		/// A sub-identity was added to an identity and the deposit paid.
		SubIdentityAdded { sub: T::AccountId, main: T::AccountId, deposit: BalanceOf<T> },
		/// An account's sub-identities were set (in bulk).
		SubIdentitiesSet { main: T::AccountId, number_of_subs: u32, new_deposit: BalanceOf<T> },
		/// A given sub-account's associated name was changed by its super-identity.
		SubIdentityRenamed { sub: T::AccountId, main: T::AccountId },
		/// A sub-identity was removed from an identity and the deposit freed.
		SubIdentityRemoved { sub: T::AccountId, main: T::AccountId, deposit: BalanceOf<T> },
		/// A sub-identity was cleared, and the given deposit repatriated from the
		/// main identity account to the sub-identity account.
		SubIdentityRevoked { sub: T::AccountId, main: T::AccountId, deposit: BalanceOf<T> },
		/// A username authority was added.
		AuthorityAdded { authority: T::AccountId },
		/// A username authority was removed.
		AuthorityRemoved { authority: T::AccountId },
		/// A username was set for `who`.
		UsernameSet { who: T::AccountId, username: Username<T> },
		/// A username was queued, but `who` must accept it prior to `expiration`.
		UsernameQueued { who: T::AccountId, username: Username<T>, expiration: BlockNumberFor<T> },
		/// A queued username passed its expiration without being claimed and was removed.
		PreapprovalExpired { whose: T::AccountId },
		/// A username was set as a primary and can be looked up from `who`.
		PrimaryUsernameSet { who: T::AccountId, username: Username<T> },
		/// A dangling username (as in, a username corresponding to an account that has removed its
		/// identity) has been removed.
		DanglingUsernameRemoved { who: T::AccountId, username: Username<T> },
		/// A username has been unbound.
		UsernameUnbound { username: Username<T> },
		/// A username has been removed.
		UsernameRemoved { username: Username<T> },
		/// A username has been killed.
		UsernameKilled { username: Username<T> },
		/// A username has been reported.
		UsernameReported { reporter: T::AccountId, username: Username<T> },
		/// An identity for a person has been set.
		PersonalIdentitySet { alias: Alias, account: T::AccountId, username: Username<T> },
		/// Evidence for a credential has beed submitted by a person.
		EvidenceSubmitted { alias: Alias },
		/// A credential was accepted for a person.
		CredentialAccepted { alias: Alias },
		/// A credential was rejected for a person.
		CredentialRejected { alias: Alias },
		/// Person was banned for sending contemptuous evidence.
		PersonBanned { alias: Alias },
		/// A personal identity was cleared.
		PersonalIdentityCleared { alias: Alias },
		/// A reported username was judged valid.
		ReportedUsernameJudgedValid { username: Username<T> },
		/// A reported username was judged invalid.
		ReportedUsernameJudgedInvalid { username: Username<T> },
		/// The judgment regarding a reported username was unclear or uncertain.
		ReportedUsernameWeakOrUnclearJudgement { username: Username<T>, judgement: OracleJudgement },
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn integrity_test() {
			assert!(
				IdentityData::bound() >= Username::<T>::bound(),
				"username must fit in the credential data"
			);
		}
	}

	#[pallet::call]
	/// Identity pallet declaration.
	impl<T: Config> Pallet<T> {
		/// Add a registrar to the system.
		///
		/// The dispatch origin for this call must be `T::RegistrarOrigin`.
		///
		/// - `account`: the account of the registrar.
		///
		/// Emits `RegistrarAdded` if successful.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::add_registrar(T::MaxRegistrars::get()))]
		pub fn add_registrar(
			origin: OriginFor<T>,
			account: AccountIdLookupOf<T>,
		) -> DispatchResultWithPostInfo {
			T::RegistrarOrigin::ensure_origin(origin)?;
			let account = T::Lookup::lookup(account)?;

			let (i, registrar_count) = Registrars::<T>::try_mutate(
				|registrars| -> Result<(RegistrarIndex, usize), DispatchError> {
					registrars
						.try_push(Some(RegistrarInfo {
							account,
							fee: Zero::zero(),
							fields: Default::default(),
						}))
						.map_err(|_| Error::<T>::TooManyRegistrars)?;
					Ok(((registrars.len() - 1) as RegistrarIndex, registrars.len()))
				},
			)?;

			Self::deposit_event(Event::RegistrarAdded { registrar_index: i });

			Ok(Some(T::WeightInfo::add_registrar(registrar_count as u32)).into())
		}

		/// Set an account's identity information and reserve the appropriate deposit.
		///
		/// If the account already has identity information, the deposit is taken as part payment
		/// for the new deposit.
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// - `info`: The identity information.
		///
		/// Emits `IdentitySet` if successful.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::set_identity(T::MaxRegistrars::get()))]
		pub fn set_identity(
			origin: OriginFor<T>,
			info: Box<T::IdentityInformation>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(!AccountToAlias::<T>::contains_key(&sender), Error::<T>::InvalidTarget);

			let mut id = match IdentityOf::<T>::get(&sender) {
				Some(mut id) => {
					// Only keep non-positive judgements.
					id.judgements.retain(|j| j.1.is_sticky());
					id.info = *info;
					id
				},
				None => Registration {
					info: *info,
					judgements: BoundedVec::default(),
					deposit: Zero::zero(),
				},
			};

			let new_deposit = Self::calculate_identity_deposit(&id.info);
			let old_deposit = id.deposit;
			Self::rejig_deposit(&sender, old_deposit, new_deposit)?;

			id.deposit = new_deposit;
			let judgements = id.judgements.len();
			IdentityOf::<T>::insert(&sender, id);
			Self::deposit_event(Event::IdentitySet { who: sender });

			Ok(Some(T::WeightInfo::set_identity(judgements as u32)).into())
		}

		/// Set the sub-accounts of the sender.
		///
		/// Payment: Any aggregate balance reserved by previous `set_subs` calls will be returned
		/// and an amount `SubAccountDeposit` will be reserved for each item in `subs`.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must have a registered
		/// identity.
		///
		/// - `subs`: The identity's (new) sub-accounts.
		// TODO: This whole extrinsic screams "not optimized". For example we could
		// filter any overlap between new and old subs, and avoid reading/writing
		// to those values... We could also ideally avoid needing to write to
		// N storage items for N sub accounts. Right now the weight on this function
		// is a large overestimate due to the fact that it could potentially write
		// to 2 x T::MaxSubAccounts::get().
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::set_subs_old(T::MaxSubAccounts::get())
			.saturating_add(T::WeightInfo::set_subs_new(subs.len() as u32))
		)]
		pub fn set_subs(
			origin: OriginFor<T>,
			subs: Vec<(T::AccountId, Data)>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(!AccountToAlias::<T>::contains_key(&sender), Error::<T>::InvalidTarget);
			ensure!(IdentityOf::<T>::contains_key(&sender), Error::<T>::NotFound);
			ensure!(
				subs.len() <= T::MaxSubAccounts::get() as usize,
				Error::<T>::TooManySubAccounts
			);

			let (old_deposit, old_ids) = SubsOf::<T>::get(&sender);
			let new_deposit = Self::subs_deposit(subs.len() as u32);

			let not_other_sub =
				subs.iter().filter_map(|i| SuperOf::<T>::get(&i.0)).all(|i| i.0 == sender);
			ensure!(not_other_sub, Error::<T>::AlreadyClaimed);

			match old_deposit.cmp(&new_deposit) {
				Ordering::Greater => {
					let err_amount = T::Currency::unreserve(&sender, old_deposit - new_deposit);
					debug_assert!(err_amount.is_zero());
				},
				Ordering::Less => {
					T::Currency::reserve(&sender, new_deposit - old_deposit)?;
				},
				Ordering::Equal => {
					// do nothing if they're equal.
				},
			};

			for s in old_ids.iter() {
				SuperOf::<T>::remove(s);
			}
			let mut ids = BoundedVec::<T::AccountId, T::MaxSubAccounts>::default();
			for (id, name) in subs {
				SuperOf::<T>::insert(&id, (sender.clone(), name));
				ids.try_push(id).expect("subs length is less than T::MaxSubAccounts; qed");
			}
			let new_subs = ids.len();

			if ids.is_empty() {
				SubsOf::<T>::remove(&sender);
			} else {
				SubsOf::<T>::insert(&sender, (new_deposit, ids));
			}

			Self::deposit_event(Event::SubIdentitiesSet {
				main: sender,
				number_of_subs: new_subs as u32,
				new_deposit,
			});

			Ok(Some(
				T::WeightInfo::set_subs_old(old_ids.len() as u32) // P: Real number of old accounts removed.
					// S: New subs added
					.saturating_add(T::WeightInfo::set_subs_new(new_subs as u32)),
			)
			.into())
		}

		/// Clear an account's identity info and all sub-accounts and return all deposits.
		///
		/// Payment: All reserved balances on the account are returned.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must have a registered
		/// identity.
		///
		/// Emits `IdentityCleared` if successful.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::clear_identity(
			T::MaxRegistrars::get(),
			T::MaxSubAccounts::get(),
		))]
		pub fn clear_identity(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(!AccountToAlias::<T>::contains_key(&sender), Error::<T>::InvalidTarget);

			let (subs_deposit, sub_ids) = SubsOf::<T>::take(&sender);
			let id = IdentityOf::<T>::take(&sender).ok_or(Error::<T>::NoIdentity)?;
			let deposit = id.total_deposit().saturating_add(subs_deposit);
			for sub in sub_ids.iter() {
				SuperOf::<T>::remove(sub);
			}

			let err_amount = T::Currency::unreserve(&sender, deposit);
			debug_assert!(err_amount.is_zero());

			Self::deposit_event(Event::IdentityCleared { who: sender, deposit });

			#[allow(deprecated)]
			Ok(Some(T::WeightInfo::clear_identity(
				id.judgements.len() as u32,
				sub_ids.len() as u32,
			))
			.into())
		}

		/// Request a judgement from a registrar.
		///
		/// Payment: At most `max_fee` will be reserved for payment to the registrar if judgement
		/// given.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must have a
		/// registered identity.
		///
		/// - `reg_index`: The index of the registrar whose judgement is requested.
		/// - `max_fee`: The maximum fee that may be paid. This should just be auto-populated as:
		///
		/// ```nocompile
		/// Self::registrars().get(reg_index).unwrap().fee
		/// ```
		///
		/// Emits `JudgementRequested` if successful.
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::request_judgement(T::MaxRegistrars::get(),))]
		pub fn request_judgement(
			origin: OriginFor<T>,
			#[pallet::compact] reg_index: RegistrarIndex,
			#[pallet::compact] max_fee: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(!AccountToAlias::<T>::contains_key(&sender), Error::<T>::InvalidTarget);
			let registrars = Registrars::<T>::get();
			let registrar = registrars
				.get(reg_index as usize)
				.and_then(Option::as_ref)
				.ok_or(Error::<T>::EmptyIndex)?;
			ensure!(max_fee >= registrar.fee, Error::<T>::FeeChanged);
			let mut id = IdentityOf::<T>::get(&sender).ok_or(Error::<T>::NoIdentity)?;

			let item = (reg_index, Judgement::FeePaid(registrar.fee));
			match id.judgements.binary_search_by_key(&reg_index, |x| x.0) {
				Ok(i) =>
					if id.judgements[i].1.is_sticky() {
						return Err(Error::<T>::StickyJudgement.into())
					} else {
						id.judgements[i] = item
					},
				Err(i) =>
					id.judgements.try_insert(i, item).map_err(|_| Error::<T>::TooManyRegistrars)?,
			}

			T::Currency::reserve(&sender, registrar.fee)?;

			let judgements = id.judgements.len();
			IdentityOf::<T>::insert(&sender, id);

			Self::deposit_event(Event::JudgementRequested {
				who: sender,
				registrar_index: reg_index,
			});

			Ok(Some(T::WeightInfo::request_judgement(judgements as u32)).into())
		}

		/// Cancel a previous request.
		///
		/// Payment: A previously reserved deposit is returned on success.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must have a
		/// registered identity.
		///
		/// - `reg_index`: The index of the registrar whose judgement is no longer requested.
		///
		/// Emits `JudgementUnrequested` if successful.
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::cancel_request(T::MaxRegistrars::get()))]
		pub fn cancel_request(
			origin: OriginFor<T>,
			reg_index: RegistrarIndex,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let mut id = IdentityOf::<T>::get(&sender).ok_or(Error::<T>::NoIdentity)?;

			let pos = id
				.judgements
				.binary_search_by_key(&reg_index, |x| x.0)
				.map_err(|_| Error::<T>::NotFound)?;
			let fee = if let Judgement::FeePaid(fee) = id.judgements.remove(pos).1 {
				fee
			} else {
				return Err(Error::<T>::JudgementGiven.into())
			};

			let err_amount = T::Currency::unreserve(&sender, fee);
			debug_assert!(err_amount.is_zero());
			let judgements = id.judgements.len();
			IdentityOf::<T>::insert(&sender, id);

			Self::deposit_event(Event::JudgementUnrequested {
				who: sender,
				registrar_index: reg_index,
			});

			Ok(Some(T::WeightInfo::cancel_request(judgements as u32)).into())
		}

		/// Set the fee required for a judgement to be requested from a registrar.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must be the account
		/// of the registrar whose index is `index`.
		///
		/// - `index`: the index of the registrar whose fee is to be set.
		/// - `fee`: the new fee.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::set_fee(T::MaxRegistrars::get()))]
		pub fn set_fee(
			origin: OriginFor<T>,
			#[pallet::compact] index: RegistrarIndex,
			#[pallet::compact] fee: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let who = ensure_signed(origin)?;

			let registrars = Registrars::<T>::mutate(|rs| -> Result<usize, DispatchError> {
				rs.get_mut(index as usize)
					.and_then(|x| x.as_mut())
					.and_then(|r| {
						if r.account == who {
							r.fee = fee;
							Some(())
						} else {
							None
						}
					})
					.ok_or_else(|| DispatchError::from(Error::<T>::InvalidIndex))?;
				Ok(rs.len())
			})?;
			Ok(Some(T::WeightInfo::set_fee(registrars as u32)).into())
		}

		/// Change the account associated with a registrar.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must be the account
		/// of the registrar whose index is `index`.
		///
		/// - `index`: the index of the registrar whose fee is to be set.
		/// - `new`: the new account ID.
		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::set_account_id(T::MaxRegistrars::get()))]
		pub fn set_account_id(
			origin: OriginFor<T>,
			#[pallet::compact] index: RegistrarIndex,
			new: AccountIdLookupOf<T>,
		) -> DispatchResultWithPostInfo {
			let who = ensure_signed(origin)?;
			let new = T::Lookup::lookup(new)?;

			let registrars = Registrars::<T>::mutate(|rs| -> Result<usize, DispatchError> {
				rs.get_mut(index as usize)
					.and_then(|x| x.as_mut())
					.and_then(|r| {
						if r.account == who {
							r.account = new;
							Some(())
						} else {
							None
						}
					})
					.ok_or_else(|| DispatchError::from(Error::<T>::InvalidIndex))?;
				Ok(rs.len())
			})?;
			Ok(Some(T::WeightInfo::set_account_id(registrars as u32)).into())
		}

		/// Set the field information for a registrar.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must be the account
		/// of the registrar whose index is `index`.
		///
		/// - `index`: the index of the registrar whose fee is to be set.
		/// - `fields`: the fields that the registrar concerns themselves with.
		#[pallet::call_index(8)]
		#[pallet::weight(T::WeightInfo::set_fields(T::MaxRegistrars::get()))]
		pub fn set_fields(
			origin: OriginFor<T>,
			#[pallet::compact] index: RegistrarIndex,
			fields: <T::IdentityInformation as IdentityInformationProvider>::FieldsIdentifier,
		) -> DispatchResultWithPostInfo {
			let who = ensure_signed(origin)?;

			let registrars =
				Registrars::<T>::mutate(|registrars| -> Result<usize, DispatchError> {
					let registrar = registrars
						.get_mut(index as usize)
						.and_then(|r| r.as_mut())
						.filter(|r| r.account == who)
						.ok_or_else(|| DispatchError::from(Error::<T>::InvalidIndex))?;
					registrar.fields = fields;

					Ok(registrars.len())
				})?;
			Ok(Some(T::WeightInfo::set_fields(registrars as u32)).into())
		}

		/// Provide a judgement for an account's identity.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must be the account
		/// of the registrar whose index is `reg_index`.
		///
		/// - `reg_index`: the index of the registrar whose judgement is being made.
		/// - `target`: the account whose identity the judgement is upon. This must be an account
		///   with a registered identity.
		/// - `judgement`: the judgement of the registrar of index `reg_index` about `target`.
		/// - `identity`: The hash of the [`IdentityInformationProvider`] for that the judgement is
		///   provided.
		///
		/// Note: Judgements do not apply to a username.
		///
		/// Emits `JudgementGiven` if successful.
		#[pallet::call_index(9)]
		#[pallet::weight(T::WeightInfo::provide_judgement(T::MaxRegistrars::get()))]
		pub fn provide_judgement(
			origin: OriginFor<T>,
			#[pallet::compact] reg_index: RegistrarIndex,
			target: AccountIdLookupOf<T>,
			judgement: Judgement<BalanceOf<T>>,
			identity: T::Hash,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let target = T::Lookup::lookup(target)?;
			ensure!(!judgement.has_deposit(), Error::<T>::InvalidJudgement);
			Registrars::<T>::get()
				.get(reg_index as usize)
				.and_then(Option::as_ref)
				.filter(|r| r.account == sender)
				.ok_or(Error::<T>::InvalidIndex)?;
			let mut id = IdentityOf::<T>::get(&target).ok_or(Error::<T>::InvalidTarget)?;

			if T::Hashing::hash_of(&id.info) != identity {
				return Err(Error::<T>::JudgementForDifferentIdentity.into())
			}

			let item = (reg_index, judgement);
			match id.judgements.binary_search_by_key(&reg_index, |x| x.0) {
				Ok(position) => {
					if let Judgement::FeePaid(fee) = id.judgements[position].1 {
						T::Currency::repatriate_reserved(
							&target,
							&sender,
							fee,
							BalanceStatus::Free,
						)
						.map_err(|_| Error::<T>::JudgementPaymentFailed)?;
					}
					id.judgements[position] = item
				},
				Err(position) => id
					.judgements
					.try_insert(position, item)
					.map_err(|_| Error::<T>::TooManyRegistrars)?,
			}

			let judgements = id.judgements.len();
			IdentityOf::<T>::insert(&target, id);
			Self::deposit_event(Event::JudgementGiven { target, registrar_index: reg_index });

			Ok(Some(T::WeightInfo::provide_judgement(judgements as u32)).into())
		}

		/// Remove an account's identity and sub-account information and slash the deposits.
		///
		/// Payment: Reserved balances from `set_subs` and `set_identity` are slashed and handled by
		/// `Slash`. Verification request deposits are not returned; they should be cancelled
		/// manually using `cancel_request`.
		///
		/// The dispatch origin for this call must match `T::ForceOrigin`.
		///
		/// - `target`: the account whose identity the judgement is upon. This must be an account
		///   with a registered identity.
		///
		/// Emits `IdentityKilled` if successful.
		#[pallet::call_index(10)]
		#[pallet::weight(T::WeightInfo::kill_identity(
			T::MaxRegistrars::get(),
			T::MaxSubAccounts::get(),
		))]
		pub fn kill_identity(
			origin: OriginFor<T>,
			target: AccountIdLookupOf<T>,
		) -> DispatchResultWithPostInfo {
			T::ForceOrigin::ensure_origin(origin)?;

			// Figure out who we're meant to be clearing.
			let target = T::Lookup::lookup(target)?;
			// Grab their deposit (and check that they have one).
			let (subs_deposit, sub_ids) = SubsOf::<T>::take(&target);
			let id = IdentityOf::<T>::take(&target).ok_or(Error::<T>::NoIdentity)?;
			let deposit = id.total_deposit().saturating_add(subs_deposit);
			for sub in sub_ids.iter() {
				SuperOf::<T>::remove(sub);
			}
			// Slash their deposit from them.
			T::Slashed::on_unbalanced(T::Currency::slash_reserved(&target, deposit).0);

			Self::deposit_event(Event::IdentityKilled { who: target, deposit });

			#[allow(deprecated)]
			Ok(Some(T::WeightInfo::kill_identity(id.judgements.len() as u32, sub_ids.len() as u32))
				.into())
		}

		/// Add the given account to the sender's subs.
		///
		/// Payment: Balance reserved by a previous `set_subs` call for one sub will be repatriated
		/// to the sender.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must have a registered
		/// sub identity of `sub`.
		#[pallet::call_index(11)]
		#[pallet::weight(T::WeightInfo::add_sub(T::MaxSubAccounts::get()))]
		pub fn add_sub(
			origin: OriginFor<T>,
			sub: AccountIdLookupOf<T>,
			data: Data,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			ensure!(!AccountToAlias::<T>::contains_key(&sender), Error::<T>::InvalidTarget);
			let sub = T::Lookup::lookup(sub)?;
			ensure!(IdentityOf::<T>::contains_key(&sender), Error::<T>::NoIdentity);

			// Check if it's already claimed as sub-identity.
			ensure!(!SuperOf::<T>::contains_key(&sub), Error::<T>::AlreadyClaimed);

			SubsOf::<T>::try_mutate(&sender, |(ref mut subs_deposit, ref mut sub_ids)| {
				// Ensure there is space and that the deposit is paid.
				ensure!(
					sub_ids.len() < T::MaxSubAccounts::get() as usize,
					Error::<T>::TooManySubAccounts
				);
				let deposit = T::SubAccountDeposit::get();
				T::Currency::reserve(&sender, deposit)?;

				SuperOf::<T>::insert(&sub, (sender.clone(), data));
				sub_ids.try_push(sub.clone()).expect("sub ids length checked above; qed");
				*subs_deposit = subs_deposit.saturating_add(deposit);

				Self::deposit_event(Event::SubIdentityAdded { sub, main: sender.clone(), deposit });
				Ok(())
			})
		}

		/// Alter the associated name of the given sub-account.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must have a registered
		/// sub identity of `sub`.
		#[pallet::call_index(12)]
		#[pallet::weight(T::WeightInfo::rename_sub(T::MaxSubAccounts::get()))]
		pub fn rename_sub(
			origin: OriginFor<T>,
			sub: AccountIdLookupOf<T>,
			data: Data,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			let sub = T::Lookup::lookup(sub)?;
			ensure!(IdentityOf::<T>::contains_key(&sender), Error::<T>::NoIdentity);
			ensure!(SuperOf::<T>::get(&sub).is_some_and(|x| x.0 == sender), Error::<T>::NotOwned);
			SuperOf::<T>::insert(&sub, (&sender, data));

			Self::deposit_event(Event::SubIdentityRenamed { main: sender, sub });
			Ok(())
		}

		/// Remove the given account from the sender's subs.
		///
		/// Payment: Balance reserved by a previous `set_subs` call for one sub will be repatriated
		/// to the sender.
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must have a registered
		/// sub identity of `sub`.
		#[pallet::call_index(13)]
		#[pallet::weight(T::WeightInfo::remove_sub(T::MaxSubAccounts::get()))]
		pub fn remove_sub(origin: OriginFor<T>, sub: AccountIdLookupOf<T>) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			ensure!(IdentityOf::<T>::contains_key(&sender), Error::<T>::NoIdentity);
			let sub = T::Lookup::lookup(sub)?;
			let (sup, _) = SuperOf::<T>::get(&sub).ok_or(Error::<T>::NotSub)?;
			ensure!(sup == sender, Error::<T>::NotOwned);
			SuperOf::<T>::remove(&sub);
			SubsOf::<T>::mutate(&sup, |(ref mut subs_deposit, ref mut sub_ids)| {
				sub_ids.retain(|x| x != &sub);
				let deposit = T::SubAccountDeposit::get().min(*subs_deposit);
				*subs_deposit -= deposit;
				let err_amount = T::Currency::unreserve(&sender, deposit);
				debug_assert!(err_amount.is_zero());
				Self::deposit_event(Event::SubIdentityRemoved { sub, main: sender, deposit });
			});
			Ok(())
		}

		/// Remove the sender as a sub-account.
		///
		/// Payment: Balance reserved by a previous `set_subs` call for one sub will be repatriated
		/// to the sender (*not* the original depositor).
		///
		/// The dispatch origin for this call must be _Signed_ and the sender must have a registered
		/// super-identity.
		///
		/// NOTE: This should not normally be used, but is provided in the case that the non-
		/// controller of an account is maliciously registered as a sub-account.
		#[pallet::call_index(14)]
		#[pallet::weight(T::WeightInfo::quit_sub(T::MaxSubAccounts::get()))]
		pub fn quit_sub(origin: OriginFor<T>) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			let (sup, _) = SuperOf::<T>::take(&sender).ok_or(Error::<T>::NotSub)?;
			SubsOf::<T>::mutate(&sup, |(ref mut subs_deposit, ref mut sub_ids)| {
				sub_ids.retain(|x| x != &sender);
				let deposit = T::SubAccountDeposit::get().min(*subs_deposit);
				*subs_deposit -= deposit;
				let _ =
					T::Currency::repatriate_reserved(&sup, &sender, deposit, BalanceStatus::Free);
				Self::deposit_event(Event::SubIdentityRevoked {
					sub: sender,
					main: sup.clone(),
					deposit,
				});
			});
			Ok(())
		}

		/// Add an `AccountId` with permission to grant usernames with a given `suffix` appended.
		///
		/// The authority can grant up to `allocation` usernames. To top up the allocation or
		/// change the account used to grant usernames, this call can be used with the updated
		/// parameters to overwrite the existing configuration.
		#[pallet::call_index(15)]
		#[pallet::weight(T::WeightInfo::add_username_authority())]
		pub fn add_username_authority(
			origin: OriginFor<T>,
			authority: AccountIdLookupOf<T>,
			suffix: Vec<u8>,
			allocation: u32,
		) -> DispatchResult {
			T::UsernameAuthorityOrigin::ensure_origin(origin)?;
			let authority = T::Lookup::lookup(authority)?;
			// We don't need to check the length because it gets checked when casting into a
			// `BoundedVec`.
			Self::validate_suffix(&suffix)?;
			let suffix = Suffix::<T>::try_from(suffix).map_err(|_| Error::<T>::InvalidSuffix)?;
			// The call is `UsernameAuthorityOrigin` guarded, overwrite the old entry if it exists.
			AuthorityOf::<T>::insert(
				&suffix,
				AuthorityProperties::<T::AccountId> { account_id: authority.clone(), allocation },
			);
			Self::deposit_event(Event::AuthorityAdded { authority });
			Ok(())
		}

		/// Remove `authority` from the username authorities.
		#[pallet::call_index(16)]
		#[pallet::weight(T::WeightInfo::remove_username_authority())]
		pub fn remove_username_authority(
			origin: OriginFor<T>,
			suffix: Vec<u8>,
			authority: AccountIdLookupOf<T>,
		) -> DispatchResult {
			T::UsernameAuthorityOrigin::ensure_origin(origin)?;
			let suffix = Suffix::<T>::try_from(suffix).map_err(|_| Error::<T>::InvalidSuffix)?;
			let authority = T::Lookup::lookup(authority)?;
			let properties =
				AuthorityOf::<T>::take(&suffix).ok_or(Error::<T>::NotUsernameAuthority)?;
			ensure!(properties.account_id == authority, Error::<T>::InvalidSuffix);
			Self::deposit_event(Event::AuthorityRemoved { authority });
			Ok(())
		}

		/// Set the username for `who`. Must be called by a username authority.
		///
		/// If `use_allocation` is set, the authority must have a username allocation available to
		/// spend. Otherwise, the authority will need to put up a deposit for registering the
		/// username.
		///
		/// Users can either pre-sign their usernames or
		/// accept them later.
		///
		/// Usernames must:
		///   - Only contain lowercase ASCII characters or digits.
		///   - When combined with the suffix of the issuing authority be _less than_ the
		///     `MaxUsernameLength`.
		#[pallet::call_index(17)]
		#[pallet::weight(T::WeightInfo::set_username_for(if *use_allocation { 1 } else { 0 }))]
		pub fn set_username_for(
			origin: OriginFor<T>,
			who: AccountIdLookupOf<T>,
			username: Vec<u8>,
			signature: Option<T::OffchainSignature>,
			use_allocation: bool,
		) -> DispatchResult {
			// Ensure origin is a Username Authority and has an allocation. Decrement their
			// allocation by one.
			let sender = ensure_signed(origin)?;
			let suffix = Self::validate_username(&username)?;
			let provider = AuthorityOf::<T>::try_mutate(
				&suffix,
				|maybe_authority| -> Result<ProviderOf<T>, DispatchError> {
					let properties =
						maybe_authority.as_mut().ok_or(Error::<T>::NotUsernameAuthority)?;
					ensure!(properties.account_id == sender, Error::<T>::NotUsernameAuthority);
					if use_allocation {
						ensure!(properties.allocation > 0, Error::<T>::NoAllocation);
						properties.allocation.saturating_dec();
						Ok(Provider::new_with_allocation())
					} else {
						let deposit = T::UsernameDeposit::get();
						T::Currency::reserve(&sender, deposit)?;
						Ok(Provider::new_with_deposit(deposit))
					}
				},
			)?;

			let bounded_username =
				Username::<T>::try_from(username).map_err(|_| Error::<T>::InvalidUsername)?;

			// Usernames must be unique. Ensure it's not taken.
			ensure!(
				!UsernameInfoOf::<T>::contains_key(&bounded_username),
				Error::<T>::UsernameTaken
			);
			ensure!(
				!PendingUsernames::<T>::contains_key(&bounded_username),
				Error::<T>::UsernameTaken
			);

			// Insert or queue.
			let who = T::Lookup::lookup(who)?;
			if let Some(s) = signature {
				// Account has pre-signed an authorization. Verify the signature provided and grant
				// the username directly.
				Self::validate_signature(&bounded_username[..], &s, &who)?;
				Self::insert_username(&who, bounded_username, provider);
			} else {
				// The user must accept the username, therefore, queue it.
				Self::queue_acceptance(&who, bounded_username, provider);
			}
			Ok(())
		}

		/// Accept a given username that an `authority` granted. The call must include the full
		/// username, as in `username.suffix`. Authorities cannot grant usernames to people, only
		/// to regular accounts.
		#[pallet::call_index(18)]
		#[pallet::weight(T::WeightInfo::accept_username())]
		pub fn accept_username(
			origin: OriginFor<T>,
			username: Username<T>,
		) -> DispatchResultWithPostInfo {
			let who = ensure_signed(origin)?;
			ensure!(!AccountToAlias::<T>::contains_key(&who), Error::<T>::InvalidTarget);
			let (approved_for, _, provider) =
				PendingUsernames::<T>::take(&username).ok_or(Error::<T>::NoUsername)?;
			ensure!(approved_for == who.clone(), Error::<T>::InvalidUsername);
			Self::insert_username(&who, username.clone(), provider);
			Self::deposit_event(Event::UsernameSet { who: who.clone(), username });
			Ok(Pays::No.into())
		}

		/// Remove an expired username approval. The username was approved by an authority but never
		/// accepted by the user and must now be beyond its expiration. The call must include the
		/// full username, as in `username.suffix`.
		#[pallet::call_index(19)]
		#[pallet::weight(T::WeightInfo::remove_expired_approval(0))]
		pub fn remove_expired_approval(
			origin: OriginFor<T>,
			username: Username<T>,
		) -> DispatchResultWithPostInfo {
			let _ = ensure_signed(origin)?;
			if let Some((who, expiration, provider)) = PendingUsernames::<T>::take(&username) {
				let now = frame_system::Pallet::<T>::block_number();
				ensure!(now > expiration, Error::<T>::NotExpired);
				let actual_weight = match provider {
					Provider::AuthorityDeposit(deposit) => {
						let suffix = Self::suffix_of_username(&username)
							.ok_or(Error::<T>::InvalidUsername)?;
						let authority_account = AuthorityOf::<T>::get(&suffix)
							.map(|auth_info| auth_info.account_id)
							.ok_or(Error::<T>::NotUsernameAuthority)?;
						let err_amount = T::Currency::unreserve(&authority_account, deposit);
						debug_assert!(err_amount.is_zero());
						T::WeightInfo::remove_expired_approval(0)
					},
					Provider::Allocation => {
						// We don't refund the allocation, it is lost, but we refund some weight.
						T::WeightInfo::remove_expired_approval(1)
					},
					Provider::System => {
						// Usernames added by the system shouldn't ever be expired.
						return Err(Error::<T>::InvalidTarget.into());
					},
				};
				Self::deposit_event(Event::PreapprovalExpired { whose: who.clone() });
				Ok((Some(actual_weight), Pays::No).into())
			} else {
				Err(Error::<T>::NoUsername.into())
			}
		}

		/// Set a given username as the primary. The username should include the suffix. Only
		/// regular accounts can set their primary username, as people can only have one username,
		/// granted through a system allocation.
		#[pallet::call_index(20)]
		#[pallet::weight(T::WeightInfo::set_primary_username())]
		pub fn set_primary_username(origin: OriginFor<T>, username: Username<T>) -> DispatchResult {
			// ensure `username` maps to `origin` (i.e. has already been set by an authority).
			let who = ensure_signed(origin)?;
			let username_info =
				UsernameInfoOf::<T>::get(&username).ok_or(Error::<T>::NoUsername)?;
			// People can't have multiple usernames.
			ensure!(!matches!(username_info.provider, Provider::System), Error::<T>::InvalidTarget);
			ensure!(who == username_info.owner, Error::<T>::InvalidUsername);
			UsernameOf::<T>::insert(&who, username.clone());
			Self::deposit_event(Event::PrimaryUsernameSet { who: who.clone(), username });
			Ok(())
		}

		/// Start the process of removing a username by placing it in the unbinding usernames map.
		/// Once the grace period has passed, the username can be deleted by calling
		/// [remove_username](crate::Call::remove_username).
		#[pallet::call_index(21)]
		#[pallet::weight(T::WeightInfo::unbind_username())]
		pub fn unbind_username(origin: OriginFor<T>, username: Username<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let username_info =
				UsernameInfoOf::<T>::get(&username).ok_or(Error::<T>::NoUsername)?;
			let suffix = Self::suffix_of_username(&username).ok_or(Error::<T>::InvalidUsername)?;
			let authority_account = AuthorityOf::<T>::get(&suffix)
				.map(|auth_info| auth_info.account_id)
				.ok_or(Error::<T>::NotUsernameAuthority)?;
			ensure!(who == authority_account, Error::<T>::NotUsernameAuthority);
			match username_info.provider {
				Provider::AuthorityDeposit(_) | Provider::Allocation => {
					let now = frame_system::Pallet::<T>::block_number();
					let grace_period_expiry = now.saturating_add(T::UsernameGracePeriod::get());
					UnbindingUsernames::<T>::try_mutate(&username, |maybe_init| {
						if maybe_init.is_some() {
							return Err(Error::<T>::AlreadyUnbinding);
						}
						*maybe_init = Some(grace_period_expiry);
						Ok(())
					})?;
				},
				Provider::System => return Err(Error::<T>::InsufficientPrivileges.into()),
			}
			Self::deposit_event(Event::UsernameUnbound { username });
			Ok(())
		}

		/// Permanently delete a username which has been unbinding for longer than the grace period.
		/// Caller is refunded the fee if the username expired and the removal was successful.
		#[pallet::call_index(22)]
		#[pallet::weight(T::WeightInfo::remove_username())]
		pub fn remove_username(
			origin: OriginFor<T>,
			username: Username<T>,
		) -> DispatchResultWithPostInfo {
			let _ = ensure_signed(origin)?;
			let grace_period_expiry =
				UnbindingUsernames::<T>::take(&username).ok_or(Error::<T>::NotUnbinding)?;
			let now = frame_system::Pallet::<T>::block_number();
			ensure!(now >= grace_period_expiry, Error::<T>::TooEarly);
			let username_info = UsernameInfoOf::<T>::take(&username)
				.defensive_proof("an unbinding username must exist")
				.ok_or(Error::<T>::NoUsername)?;
			// If this is the primary username, remove the entry from the account -> username map.
			UsernameOf::<T>::mutate(&username_info.owner, |maybe_primary| {
				if maybe_primary.as_ref().is_some_and(|primary| *primary == username) {
					*maybe_primary = None;
				}
			});
			match username_info.provider {
				Provider::AuthorityDeposit(username_deposit) => {
					let suffix = Self::suffix_of_username(&username)
						.defensive_proof("registered username must be valid")
						.ok_or(Error::<T>::InvalidUsername)?;
					if let Some(authority_account) =
						AuthorityOf::<T>::get(&suffix).map(|auth_info| auth_info.account_id)
					{
						let err_amount =
							T::Currency::unreserve(&authority_account, username_deposit);
						debug_assert!(err_amount.is_zero());
					}
				},
				Provider::Allocation => {
					// We don't refund the allocation, it is lost.
				},
				Provider::System => return Err(Error::<T>::InsufficientPrivileges.into()),
			}
			Self::deposit_event(Event::UsernameRemoved { username });
			Ok(Pays::No.into())
		}

		/// Call with [ForceOrigin](crate::Config::ForceOrigin) privileges which deletes a username
		/// and slashes any deposit associated with it.
		#[pallet::call_index(23)]
		#[pallet::weight(T::WeightInfo::kill_username(0))]
		pub fn kill_username(
			origin: OriginFor<T>,
			username: Username<T>,
		) -> DispatchResultWithPostInfo {
			T::ForceOrigin::ensure_origin(origin)?;
			let username_info =
				UsernameInfoOf::<T>::take(&username).ok_or(Error::<T>::NoUsername)?;
			// If this is the primary username, remove the entry from the account -> username map.
			UsernameOf::<T>::mutate(&username_info.owner, |maybe_primary| {
				if matches!(maybe_primary, Some(primary) if *primary == username) {
					*maybe_primary = None;
				}
			});
			let _ = UnbindingUsernames::<T>::take(&username);
			let actual_weight = match username_info.provider {
				Provider::AuthorityDeposit(username_deposit) => {
					let suffix =
						Self::suffix_of_username(&username).ok_or(Error::<T>::InvalidUsername)?;
					if let Some(authority_account) =
						AuthorityOf::<T>::get(&suffix).map(|auth_info| auth_info.account_id)
					{
						T::Slashed::on_unbalanced(
							T::Currency::slash_reserved(&authority_account, username_deposit).0,
						);
					}
					T::WeightInfo::kill_username(0)
				},
				Provider::Allocation => {
					// We don't refund the allocation, it is lost, but we do refund some weight.
					T::WeightInfo::kill_username(1)
				},
				Provider::System => {
					// Force origin can remove system usernames.
					T::WeightInfo::kill_username(1)
				},
			};
			Self::deposit_event(Event::UsernameKilled { username });
			Ok((Some(actual_weight), Pays::No).into())
		}

		/// Sets the username and on-chain account for a person, along with an empty identity which
		/// can only be populated using an oracle through the social credential verification system.
		/// The chosen username must be domainless.
		///
		/// The sender must sign the alias using the key associated with the provided on-chain
		/// account to prove ownership.
		///
		/// The dispatch origin for this call must be the contextual alias of the person and the
		/// sender must not have already registered their identity and username.
		///
		/// Emits `PersonalIdentitySet` if successful.
		#[pallet::call_index(24)]
		#[pallet::weight(T::WeightInfo::set_personal_identity())]
		pub fn set_personal_identity(
			origin: OriginFor<T>,
			account: T::AccountId,
			signature: T::OffchainSignature,
			username: Username<T>,
		) -> DispatchResult {
			let alias = T::EnsurePerson::ensure_origin(origin, &IDENTITY_CONTEXT)?;

			// Make sure the username is valid.
			Self::validate_personal_username(&username)?;

			ensure!(!PersonIdentities::<T>::contains_key(alias), Error::<T>::AlreadyRegistered);
			ensure!(!IdentityOf::<T>::contains_key(&account), Error::<T>::AlreadyRegistered);
			ensure!(!UsernameOf::<T>::contains_key(&account), Error::<T>::AlreadyRegistered);
			ensure!(!AccountToAlias::<T>::contains_key(&account), Error::<T>::AlreadyRegistered);
			ensure!(!UsernameInfoOf::<T>::contains_key(&username), Error::<T>::AlreadyRegistered);
			ensure!(signature.verify(&alias[..], &account), Error::<T>::InvalidSignature);

			let id = Registration {
				info: Default::default(),
				judgements: alloc::vec![(RegistrarIndex::MAX, Judgement::External)]
					.try_into()
					.expect("judgements must be able to hold at least one element; qed"),
				deposit: Zero::zero(),
			};
			IdentityOf::<T>::insert(&account, id);
			PersonIdentities::<T>::insert(alias, PersonalIdentity::new(account.clone()));
			AccountToAlias::<T>::insert(&account, alias);
			UsernameOf::<T>::insert(&account, &username);
			let username_info =
				UsernameInformation { owner: account.clone(), provider: Provider::new_permanent() };
			UsernameInfoOf::<T>::insert(&username, username_info);
			Self::deposit_event(Event::PersonalIdentitySet { alias, account, username });

			Ok(())
		}

		/// Open a case for an oracle to judge a social credential of a person.
		///
		/// The dispatch origin for this call must be the contextual alias of the person and the
		/// sender must have a registered identity.
		///
		/// Emits `EvidenceSubmitted` if successful.
		#[pallet::call_index(25)]
		#[pallet::weight(T::WeightInfo::submit_personal_credential_evidence())]
		pub fn submit_personal_credential_evidence(
			origin: OriginFor<T>,
			credential: Social,
		) -> DispatchResultWithPostInfo {
			let alias = T::EnsurePerson::ensure_origin(origin, &IDENTITY_CONTEXT)?;
			let mut personal_identity =
				PersonIdentities::<T>::get(alias).ok_or(Error::<T>::NotFound)?;
			ensure!(!personal_identity.banned, Error::<T>::Banned);
			ensure!(!personal_identity.pending_social(&credential), Error::<T>::AlreadyClaimed);
			ensure!(!personal_identity.pending_judgements.is_full(), Error::<T>::JudgementListFull);
			let username =
				UsernameOf::<T>::get(&personal_identity.account).ok_or(Error::<T>::NoIdentity)?;

			let context = JudgementContext::truncate_from(alias.to_vec());
			let callback = Callback::from_parts(Pallet::<T>::index() as u8, 26); // Call::<T>::judged();

			let evidence: IdentityData = username
				.into_inner()
				.try_into()
				.expect("username fits in the credential data, checked in integrity test; qed");
			let statement =
				Statement::IdentityCredential { platform: credential.clone(), evidence };
			let id = T::Oracle::judge_statement(statement, context, callback)?;
			personal_identity
				.pending_judgements
				.try_push((credential, id))
				.expect("len and previous existence checked above; qed");
			PersonIdentities::<T>::insert(alias, personal_identity);

			Self::deposit_event(Event::EvidenceSubmitted { alias });

			Ok(Pays::No.into())
		}

		/// Callback to enforce the judgement of a social credential. This is to be called only by
		/// the oracle that judged the case.
		#[pallet::call_index(26)]
		#[pallet::weight(T::WeightInfo::personal_credential_judged())]
		pub fn personal_credential_judged(
			origin: OriginFor<T>,
			ticket: OracleTicketOf<T>,
			context: JudgementContext,
			judgement: OracleJudgement,
		) -> DispatchResultWithPostInfo {
			ensure_root(origin)?;
			let alias = Alias::decode(&mut &context[..]).map_err(|_| Error::<T>::BadContext)?;
			let mut personal_identity =
				PersonIdentities::<T>::get(alias).ok_or(Error::<T>::NotFound)?;
			let social =
				personal_identity.take_pending(ticket).ok_or(Error::<T>::UnexpectedJudgement)?;
			let mut registration =
				IdentityOf::<T>::get(&personal_identity.account).ok_or(Error::<T>::NoIdentity)?;

			match judgement {
				OracleJudgement::Truth(Truth::True) => {
					registration.info.set_social(social).map_err(|_| Error::<T>::NotSupported)?;
					IdentityOf::<T>::insert(&personal_identity.account, registration);
					PersonIdentities::<T>::insert(alias, &personal_identity);
					Self::deposit_event(Event::CredentialAccepted { alias });
				},
				OracleJudgement::Truth(Truth::False) => {
					// We give the user another chance.
					Self::deposit_event(Event::CredentialRejected { alias });
				},
				OracleJudgement::Contempt => {
					// The user will receive a ban in order to prevent spam.
					personal_identity.banned = true;
					PersonIdentities::<T>::insert(alias, personal_identity);
					Self::deposit_event(Event::PersonBanned { alias });
				},
			}

			Ok(Pays::No.into())
		}

		/// Clear a person's identity info. The sender must pay a penalty through the associated
		/// alias account for removing the identity.
		///
		/// The dispatch origin for this call must be the contextual alias of the person and the
		/// sender must have a registered identity.
		///
		/// Emits `IdentityPersonalCleared` if successful.
		#[pallet::call_index(27)]
		#[pallet::weight(T::WeightInfo::clear_personal_identity())]
		pub fn clear_personal_identity(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
			let alias = T::EnsurePerson::ensure_origin(origin, &IDENTITY_CONTEXT)?;

			// If a username was reported, one cannot remove their identity as a way to evade the
			// judgement.
			ensure!(
				!PendingUsernameReports::<T>::contains_key(alias),
				Error::<T>::UsernameJudgementOngoing
			);

			let personal_identity =
				PersonIdentities::<T>::take(alias).ok_or(Error::<T>::NotFound)?;
			// People shouldn't be able to set subs.
			debug_assert!(!SubsOf::<T>::contains_key(&personal_identity.account));
			let _ = AccountToAlias::<T>::take(&personal_identity.account)
				.ok_or(Error::<T>::NotFound)?;
			let _ =
				IdentityOf::<T>::take(&personal_identity.account).ok_or(Error::<T>::NoIdentity)?;
			let username =
				UsernameOf::<T>::take(&personal_identity.account).ok_or(Error::<T>::NoUsername)?;
			ensure!(
				matches!(
					UsernameInfoOf::<T>::take(&username).ok_or(Error::<T>::NoUsername)?.provider,
					Provider::System
				),
				Error::<T>::InvalidUsername
			);

			// Apply the removal penalty so that we discourage people from spamming the personal
			// identity system.
			let removal_penalty = T::CredentialRemovalPenalty::get();
			T::Slashed::on_unbalanced(T::Currency::withdraw(
				&personal_identity.account,
				removal_penalty,
				WithdrawReasons::FEE,
				ExistenceRequirement::AllowDeath,
			)?);

			Self::deposit_event(Event::PersonalIdentityCleared { alias });

			Ok(Pays::No.into())
		}

		/// Report a username as invalid/offensive/wrong/anything else.
		///
		/// The dispatch origin for this call must be a signed extrinsic.
		///
		/// - `username`: The username to be reported.
		#[pallet::call_index(28)]
		#[pallet::weight(T::WeightInfo::report_username())]
		pub fn report_username(origin: OriginFor<T>, username: Username<T>) -> DispatchResult {
			let reporter_account = ensure_signed(origin.clone())?;

			// Make sure the username exists
			let username_info =
				UsernameInfoOf::<T>::get(username.clone()).ok_or(Error::<T>::NoUsername)?;
			// Make sure the username was issued by the system
			ensure!(
				username_info.provider == Provider::System,
				Error::<T>::NotSystemProvidedUsername
			);

			// Find the identity behind the reported username
			let alias =
				AccountToAlias::<T>::get(&username_info.owner).ok_or(Error::<T>::NoAlias)?;
			let mut personal_identity =
				PersonIdentities::<T>::get(alias).ok_or(Error::<T>::NoIdentity)?;
			let statement_username: IdentityData = username
				.clone()
				.into_inner()
				.try_into()
				.expect("username matches the credential data, checked in integrity test; qed");

			// Check if there already is a pending report for this alias
			ensure!(!PendingUsernameReports::<T>::contains_key(alias), Error::<T>::AlreadyReported);

			// Check if the timeout to report the username again has passed
			let current_block = <frame_system::Pallet<T>>::block_number();
			if let Some(reported_at) = personal_identity.username_last_reported_at {
				ensure!(
					current_block.saturating_sub(reported_at) > T::UsernameReportTimeout::get(),
					Error::<T>::LastUsernameReportTooRecent
				);
			};

			// Take a deposit from the reporter
			T::Currency::reserve(&reporter_account, T::UsernameReportDeposit::get())?;

			let context = JudgementContext::truncate_from(alias.to_vec());

			// call_index 29 refers to callback fn reported_username_judged
			let callback = Callback::from_parts(Pallet::<T>::index() as u8, 29);

			let statement = Statement::UsernameValid { username: statement_username };
			let case_id = T::Oracle::judge_statement(statement, context, callback)?;

			let username_report = UsernameReport {
				reporter: reporter_account.clone(),
				username: username.clone(),
				case_id,
			};
			PendingUsernameReports::<T>::insert(alias, username_report);

			// Store the block at which the username was reported
			personal_identity.username_last_reported_at = Some(current_block);
			PersonIdentities::<T>::insert(alias, personal_identity);

			Self::deposit_event(Event::UsernameReported { reporter: reporter_account, username });

			Ok(())
		}

		/// Given judgement on a previously reported username either:
		/// 1. In case username was found valid:
		/// - slashes the amount deposited by the reporter,
		/// - does nothing to the identity behind the reported username,
		/// 2. In case username was found invalid:
		/// - returns the deposited funds to the reporter,
		/// - bans the identity behind the reported username.
		/// Serves as a callback used upon judgement request to the oracle.
		/// Must only be used by the statement oracle.
		#[pallet::call_index(29)]
		#[pallet::weight(T::WeightInfo::reported_username_judged_false().max(T::WeightInfo::reported_username_judged_true()))]
		pub fn reported_username_judged(
			origin: OriginFor<T>,
			ticket: crate::OracleTicketOf<T>,
			context: JudgementContext,
			judgement: OracleJudgement,
		) -> DispatchResultWithPostInfo {
			ensure_root(origin)?;
			let alias = Alias::decode(&mut &context[..]).map_err(|_| Error::<T>::BadContext)?;
			let mut personal_identity =
				PersonIdentities::<T>::get(alias).ok_or(Error::<T>::NoIdentity)?;

			let username_report =
				PendingUsernameReports::<T>::take(alias).ok_or(Error::<T>::UnexpectedJudgement)?;
			ensure!(username_report.case_id == ticket, Error::<T>::UnexpectedJudgement);

			let actual_weight = match judgement {
				OracleJudgement::Truth(Truth::True) => {
					// Username found valid.
					// Slash reporter's deposit.
					T::Slashed::on_unbalanced(
						T::Currency::slash_reserved(
							&username_report.reporter,
							T::UsernameReportDeposit::get(),
						)
						.0,
					);

					Self::deposit_event(Event::ReportedUsernameJudgedValid {
						username: username_report.username.clone(),
					});

					T::WeightInfo::reported_username_judged_true()
				},
				OracleJudgement::Truth(Truth::False) | OracleJudgement::Contempt => {
					// Username found invalid.
					// Reporter's deposit is returned to him.
					// The Identity behind the username is banned.
					let err_amount = T::Currency::unreserve(
						&username_report.reporter,
						T::UsernameReportDeposit::get(),
					);
					debug_assert!(err_amount.is_zero());

					personal_identity.banned = true;
					PersonIdentities::<T>::insert(alias, personal_identity);

					Self::deposit_event(Event::ReportedUsernameJudgedInvalid {
						username: username_report.username.clone(),
					});

					T::WeightInfo::reported_username_judged_false()
				},
			};

			Ok((Some(actual_weight), Pays::No).into())
		}
	}

	#[pallet::extra_constants]
	impl<T: Config> Pallet<T> {
		/// The context used for the proofs required to authenticate as a personal alias in
		/// identity.
		pub fn identity_context() -> Context {
			IDENTITY_CONTEXT
		}
	}
}

impl<T: Config> Pallet<T> {
	/// Get the subs of an account.
	pub fn subs(who: &T::AccountId) -> Vec<(T::AccountId, Data)> {
		SubsOf::<T>::get(who)
			.1
			.into_iter()
			.filter_map(|a| SuperOf::<T>::get(&a).map(|x| (a, x.1)))
			.collect()
	}

	/// Calculate the deposit required for a number of `sub` accounts.
	fn subs_deposit(subs: u32) -> BalanceOf<T> {
		T::SubAccountDeposit::get().saturating_mul(<BalanceOf<T>>::from(subs))
	}

	/// Take the `current` deposit that `who` is holding, and update it to a `new` one.
	fn rejig_deposit(
		who: &T::AccountId,
		current: BalanceOf<T>,
		new: BalanceOf<T>,
	) -> DispatchResult {
		match new.cmp(&current) {
			Ordering::Greater => {
				T::Currency::reserve(who, new - current)?;
			},
			Ordering::Less => {
				let err_amount = T::Currency::unreserve(who, current - new);
				debug_assert!(err_amount.is_zero());
			},
			Ordering::Equal => {
				// Do nothing
			},
		}
		Ok(())
	}

	/// Check if the account has corresponding identity information by the identity field.
	pub fn has_identity(
		who: &T::AccountId,
		fields: <T::IdentityInformation as IdentityInformationProvider>::FieldsIdentifier,
	) -> bool {
		IdentityOf::<T>::get(who)
			.is_some_and(|registration| (registration.info.has_identity(fields)))
	}

	/// Calculate the deposit required for an identity.
	fn calculate_identity_deposit(info: &T::IdentityInformation) -> BalanceOf<T> {
		let bytes = info.encoded_size() as u32;
		let byte_deposit = T::ByteDeposit::get().saturating_mul(<BalanceOf<T>>::from(bytes));
		T::BasicDeposit::get().saturating_add(byte_deposit)
	}

	/// Validate that a username conforms to allowed characters/format.
	///
	/// The function will validate the characters in `username`. It is expected to pass a fully
	/// formatted username here (i.e. "username.suffix"). The suffix is also separately validated
	/// and returned by this function.
	fn validate_username(username: &[u8]) -> Result<Suffix<T>, DispatchError> {
		// Verify input length before allocating a Vec with the user's input.
		ensure!(
			username.len() <= T::MaxUsernameLength::get() as usize,
			Error::<T>::InvalidUsername
		);

		// Usernames cannot be empty.
		ensure!(!username.is_empty(), Error::<T>::InvalidUsername);
		let separator_idx =
			username.iter().rposition(|c| *c == b'.').ok_or(Error::<T>::InvalidUsername)?;
		ensure!(separator_idx > 0, Error::<T>::InvalidUsername);
		let suffix_start = separator_idx.checked_add(1).ok_or(Error::<T>::InvalidUsername)?;
		ensure!(suffix_start > T::MinUsernameLength::get() as usize, Error::<T>::InvalidUsername);
		// Username must be lowercase and alphanumeric.
		ensure!(
			username
				.iter()
				.take(separator_idx)
				.all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase()),
			Error::<T>::InvalidUsername
		);
		let suffix: Suffix<T> = (username[suffix_start..])
			.to_vec()
			.try_into()
			.map_err(|_| Error::<T>::InvalidUsername)?;
		ensure!(suffix.len() >= T::MinUsernameLength::get() as usize, Error::<T>::InvalidUsername);
		Ok(suffix)
	}

	/// Validate that a personal, domainless username conforms to allowed characters/format.
	///
	/// The function will validate the characters in `username`.
	fn validate_personal_username(username: &Username<T>) -> Result<(), DispatchError> {
		// Usernames cannot be empty.
		ensure!(
			username.len() >= T::MinUsernameLength::get() as usize,
			Error::<T>::InvalidUsername
		);

		ensure!(
			username.iter().all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase()),
			Error::<T>::InvalidUsername
		);
		Ok(())
	}

	/// Return the suffix of a username, if it is valid.
	fn suffix_of_username(username: &Username<T>) -> Option<Suffix<T>> {
		let separator_idx = username.iter().rposition(|c| *c == b'.')?;
		let suffix_start = separator_idx.checked_add(1)?;
		if suffix_start >= username.len() {
			return None;
		}
		(username[suffix_start..]).to_vec().try_into().ok()
	}

	/// Validate that a suffix conforms to allowed characters/format.
	fn validate_suffix(suffix: &[u8]) -> Result<(), DispatchError> {
		ensure!(suffix.len() <= T::MaxSuffixLength::get() as usize, Error::<T>::InvalidSuffix);
		ensure!(suffix.len() >= T::MinUsernameLength::get() as usize, Error::<T>::InvalidSuffix);
		ensure!(
			suffix.iter().all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase()),
			Error::<T>::InvalidSuffix
		);
		Ok(())
	}

	/// Validate a signature. Supports signatures on raw `data` or `data` wrapped in HTML `<Bytes>`.
	pub fn validate_signature(
		data: &[u8],
		signature: &T::OffchainSignature,
		signer: &T::AccountId,
	) -> DispatchResult {
		// Happy path, user has signed the raw data.
		if signature.verify(data, signer) {
			return Ok(())
		}
		// NOTE: for security reasons modern UIs implicitly wrap the data requested to sign into
		// `<Bytes> + data + </Bytes>`, so why we support both wrapped and raw versions.
		let prefix = b"<Bytes>";
		let suffix = b"</Bytes>";
		let mut wrapped: alloc::vec::Vec<u8> =
			alloc::vec::Vec::with_capacity(data.len() + prefix.len() + suffix.len());
		wrapped.extend(prefix);
		wrapped.extend(data);
		wrapped.extend(suffix);

		ensure!(signature.verify(&wrapped[..], signer), Error::<T>::InvalidSignature);

		Ok(())
	}

	/// A username has met all conditions. Insert the relevant storage items.
	pub fn insert_username(who: &T::AccountId, username: Username<T>, provider: ProviderOf<T>) {
		// Check if they already have a primary. If so, leave it. If not, set it.
		// Likewise, check if they have an identity. If not, give them a minimal one.
		let (primary_username, new_is_primary) = match UsernameOf::<T>::get(who) {
			// User has an existing Identity and a primary username. Leave it.
			Some(primary) => (primary, false),
			// User has an Identity but no primary. Set the new one as primary.
			None => (username.clone(), true),
		};

		if new_is_primary {
			UsernameOf::<T>::insert(who, primary_username);
		}
		let username_info = UsernameInformation { owner: who.clone(), provider };
		// Enter in username map.
		UsernameInfoOf::<T>::insert(username.clone(), username_info);
		Self::deposit_event(Event::UsernameSet { who: who.clone(), username: username.clone() });
		if new_is_primary {
			Self::deposit_event(Event::PrimaryUsernameSet { who: who.clone(), username });
		}
	}

	/// A username was granted by an authority, but must be accepted by `who`. Put the username
	/// into a queue for acceptance.
	pub fn queue_acceptance(who: &T::AccountId, username: Username<T>, provider: ProviderOf<T>) {
		let now = frame_system::Pallet::<T>::block_number();
		let expiration = now.saturating_add(T::PendingUsernameExpiration::get());
		PendingUsernames::<T>::insert(&username, (who.clone(), expiration, provider));
		Self::deposit_event(Event::UsernameQueued { who: who.clone(), username, expiration });
	}

	/// Reap an identity, clearing associated storage items and refunding any deposits. This
	/// function is very similar to (a) `clear_identity`, but called on a `target` account instead
	/// of self; and (b) `kill_identity`, but without imposing a slash.
	///
	/// Parameters:
	/// - `target`: The account for which to reap identity state.
	///
	/// Return type is a tuple of the number of registrars, `IdentityInfo` bytes, and sub accounts,
	/// respectively.
	///
	/// NOTE: This function is here temporarily for migration of Identity info from the Polkadot
	/// Relay Chain into a system parachain. It will be removed after the migration.
	pub fn reap_identity(who: &T::AccountId) -> Result<(u32, u32, u32), DispatchError> {
		// `take` any storage items keyed by `target`
		// identity
		let id = IdentityOf::<T>::take(who).ok_or(Error::<T>::NoIdentity)?;
		let registrars = id.judgements.len() as u32;
		let encoded_byte_size = id.info.encoded_size() as u32;

		// subs
		let (subs_deposit, sub_ids) = <SubsOf<T>>::take(who);
		let actual_subs = sub_ids.len() as u32;
		for sub in sub_ids.iter() {
			SuperOf::<T>::remove(sub);
		}

		// unreserve any deposits
		let deposit = id.total_deposit().saturating_add(subs_deposit);
		let err_amount = T::Currency::unreserve(who, deposit);
		debug_assert!(err_amount.is_zero());
		Ok((registrars, encoded_byte_size, actual_subs))
	}

	/// Update the deposits held by `target` for its identity info.
	///
	/// Parameters:
	/// - `target`: The account for which to update deposits.
	///
	/// Return type is a tuple of the new Identity and Subs deposits, respectively.
	///
	/// NOTE: This function is here temporarily for migration of Identity info from the Polkadot
	/// Relay Chain into a system parachain. It will be removed after the migration.
	pub fn poke_deposit(
		target: &T::AccountId,
	) -> Result<(BalanceOf<T>, BalanceOf<T>), DispatchError> {
		// Identity Deposit
		let new_id_deposit = IdentityOf::<T>::try_mutate(
			target,
			|identity_of| -> Result<BalanceOf<T>, DispatchError> {
				let reg = identity_of.as_mut().ok_or(Error::<T>::NoIdentity)?;
				// Calculate what deposit should be
				let encoded_byte_size = reg.info.encoded_size() as u32;
				let byte_deposit =
					T::ByteDeposit::get().saturating_mul(BalanceOf::<T>::from(encoded_byte_size));
				let new_id_deposit = T::BasicDeposit::get().saturating_add(byte_deposit);

				// Update account
				Self::rejig_deposit(target, reg.deposit, new_id_deposit)?;

				reg.deposit = new_id_deposit;
				Ok(new_id_deposit)
			},
		)?;

		let new_subs_deposit = if SubsOf::<T>::contains_key(target) {
			SubsOf::<T>::try_mutate(
				target,
				|(current_subs_deposit, subs_of)| -> Result<BalanceOf<T>, DispatchError> {
					let new_subs_deposit = Self::subs_deposit(subs_of.len() as u32);
					Self::rejig_deposit(target, *current_subs_deposit, new_subs_deposit)?;
					*current_subs_deposit = new_subs_deposit;
					Ok(new_subs_deposit)
				},
			)?
		} else {
			// If the item doesn't exist, there is no "old" deposit, and the new one is zero, so no
			// need to call rejig, it'd just be zero -> zero.
			Zero::zero()
		};
		Ok((new_id_deposit, new_subs_deposit))
	}

	/// Set an identity with zero deposit. Used for benchmarking and XCM emulator tests that involve
	/// `rejig_deposit`.
	#[cfg(any(feature = "runtime-benchmarks", feature = "std"))]
	pub fn set_identity_no_deposit(
		who: &T::AccountId,
		info: T::IdentityInformation,
	) -> DispatchResult {
		IdentityOf::<T>::insert(
			who,
			Registration {
				judgements: Default::default(),
				deposit: Zero::zero(),
				info: info.clone(),
			},
		);
		Ok(())
	}

	/// Set subs with zero deposit and default name. Only used for benchmarks that involve
	/// `rejig_deposit`.
	#[cfg(any(feature = "runtime-benchmarks", feature = "std"))]
	pub fn set_subs_no_deposit(
		who: &T::AccountId,
		subs: Vec<(T::AccountId, Data)>,
	) -> DispatchResult {
		let mut sub_accounts = BoundedVec::<T::AccountId, T::MaxSubAccounts>::default();
		for (sub, name) in subs {
			SuperOf::<T>::insert(&sub, (who.clone(), name));
			sub_accounts
				.try_push(sub)
				.expect("benchmark should not pass more than T::MaxSubAccounts");
		}
		SubsOf::<T>::insert::<
			&T::AccountId,
			(BalanceOf<T>, BoundedVec<T::AccountId, T::MaxSubAccounts>),
		>(who, (Zero::zero(), sub_accounts));
		Ok(())
	}
}
