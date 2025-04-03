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

// Tests for Identity Pallet

use super::*;
use crate::{
	self as pallet_identity,
	legacy::{IdentityField, IdentityInfo},
};

use codec::{Decode, Encode};
use frame_support::{
	assert_err, assert_noop, assert_ok, derive_impl, parameter_types,
	traits::{
		fungible::Mutate,
		reality::{identity::Social, Alias, Data as PersonalData},
		ConstU32, ConstU64, Get, OnFinalize, OnInitialize, TryMapSuccess,
	},
	BoundedVec,
};
use frame_system::{EnsureRoot, EnsureSigned};
use sp_core::H256;
use sp_io::crypto::{sr25519_generate, sr25519_sign};
use sp_keystore::{testing::MemoryKeystore, KeystoreExt};
use sp_runtime::{
	morph_types,
	traits::{BadOrigin, BlakeTwo256, IdentifyAccount, IdentityLookup, Verify},
	BuildStorage, MultiSignature, MultiSigner,
};

type AccountIdOf<Test> = <Test as frame_system::Config>::AccountId;
pub type AccountPublic = <MultiSignature as Verify>::Signer;
pub type AccountId = <AccountPublic as IdentifyAccount>::AccountId;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system::{Pallet, Call, Config<T>, Storage, Event<T>},
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		Identity: pallet_identity::{Pallet, Call, Storage, Event<T>},
		Oracle: simple_oracle,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type RuntimeOrigin = RuntimeOrigin;
	type Nonce = u64;
	type Hash = H256;
	type RuntimeCall = RuntimeCall;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = ConstU64<250>;
	type DbWeight = ();
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = ConstU32<16>;
}

impl pallet_balances::Config for Test {
	type Balance = u64;
	type RuntimeEvent = RuntimeEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ConstU64<1>;
	type AccountStore = System;
	type MaxLocks = ();
	type MaxReserves = ();
	type ReserveIdentifier = [u8; 8];
	type WeightInfo = ();
	type FreezeIdentifier = ();
	type MaxFreezes = ();
	type RuntimeHoldReason = ();
	type RuntimeFreezeReason = ();
	type DoneSlashHandler = ();
}

#[frame_support::pallet]
pub mod simple_oracle {
	use codec::Decode;
	use frame_support::{
		Blake2_128Concat,
		__private::Get,
		pallet_prelude::{Hooks, OptionQuery, StorageMap},
		traits::reality::{
			Alias, Callback, Judgement, JudgementContext, Statement, StatementOracle,
		},
	};
	use frame_system::pallet_prelude::BlockNumberFor;
	use sp_runtime::DispatchError;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		#[pallet::constant]
		type MaxStatementsToJudge: Get<u32>;
	}

	#[pallet::storage]
	pub type StatementsToJudge<T: Config> =
		StorageMap<_, Blake2_128Concat, Alias, Statement, OptionQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	impl<T: Config> StatementOracle<T::RuntimeCall> for Pallet<T> {
		type Ticket = Alias;

		fn judge_statement(
			statement: Statement,
			ctx: JudgementContext,
			_: Callback<(Self::Ticket, JudgementContext, Judgement), T::RuntimeCall>,
		) -> Result<Self::Ticket, DispatchError> {
			let alias = Alias::decode(&mut &ctx[..]).unwrap();
			StatementsToJudge::<T>::insert(alias, statement);
			Ok(alias)
		}
	}
}

impl simple_oracle::Config for Test {
	type MaxStatementsToJudge = ConstU32<20>;
}

pub struct MockOracle;
impl StatementOracle<RuntimeCall> for MockOracle {
	type Ticket = Alias;

	fn judge_statement(
		_: Statement,
		ctx: JudgementContext,
		_: Callback<(Self::Ticket, JudgementContext, OracleJudgement), RuntimeCall>,
	) -> Result<Self::Ticket, DispatchError> {
		let alias = Alias::decode(&mut &ctx[..]).unwrap();
		Ok(alias)
	}
}

parameter_types! {
	pub const MaxAdditionalFields: u32 = 2;
	pub const MaxRegistrars: u32 = 20;
}

morph_types! {
	pub type IdenticalAlias: TryMorph = |r: AccountId| -> Result<Alias, ()> {
		Ok([<sp_runtime::AccountId32 as AsRef<[u8]>>::as_ref(&r)[0]; 32])
	};
}

impl pallet_identity::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type Slashed = ();
	type BasicDeposit = ConstU64<100>;
	type ByteDeposit = ConstU64<10>;
	type UsernameDeposit = ConstU64<10>;
	type UsernameReportDeposit = ConstU64<5>;
	type SubAccountDeposit = ConstU64<100>;
	type MaxSubAccounts = ConstU32<2>;
	type IdentityInformation = IdentityInfo<MaxAdditionalFields>;
	type MaxRegistrars = MaxRegistrars;
	type RegistrarOrigin = EnsureRoot<Self::AccountId>;
	type ForceOrigin = EnsureRoot<Self::AccountId>;
	type OffchainSignature = MultiSignature;
	type SigningPublicKey = AccountPublic;
	type UsernameAuthorityOrigin = EnsureRoot<Self::AccountId>;
	type PendingUsernameExpiration = ConstU64<100>;
	type UsernameGracePeriod = ConstU64<2>;
	type MaxSuffixLength = ConstU32<7>;
	type MaxUsernameLength = ConstU32<32>;
	type MaxJudgements = ConstU32<3>;
	type MinUsernameLength = ConstU32<2>;
	type Oracle = simple_oracle::Pallet<Test>;
	type EnsurePerson = TryMapSuccess<EnsureSigned<AccountId>, IdenticalAlias>;
	type CredentialRemovalPenalty = ConstU64<100>;
	type WeightInfo = ();
	type UsernameReportTimeout = ConstU64<5>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![
			(account(1), 100),
			(account(2), 100),
			(account(3), 100),
			(account(10), 1000),
			(account(20), 1000),
			(account(30), 1000),
		],
		..Default::default()
	}
	.assimilate_storage(&mut t)
	.unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.register_extension(KeystoreExt::new(MemoryKeystore::new()));
	ext.execute_with(|| System::set_block_number(1));
	ext
}

fn run_to_block(n: u64) {
	while System::block_number() < n {
		Identity::on_finalize(System::block_number());
		Balances::on_finalize(System::block_number());
		System::on_finalize(System::block_number());
		System::set_block_number(System::block_number() + 1);
		System::on_initialize(System::block_number());
		Balances::on_initialize(System::block_number());
		Identity::on_initialize(System::block_number());
	}
}

fn account(id: u8) -> AccountIdOf<Test> {
	[id; 32].into()
}

fn account_from_u32(id: u32) -> AccountIdOf<Test> {
	let mut buffer = [255u8; 32];
	let id_bytes = id.to_le_bytes();
	let id_size = id_bytes.len();
	for ii in 0..buffer.len() / id_size {
		let s = ii * id_size;
		let e = s + id_size;
		buffer[s..e].clone_from_slice(&id_bytes[..]);
	}
	buffer.into()
}

fn accounts() -> [AccountIdOf<Test>; 8] {
	[
		account(1),
		account(2),
		account(3),
		account(4), // unfunded
		account(10),
		account(20),
		account(30),
		account(40), // unfunded
	]
}

fn unfunded_accounts() -> [AccountIdOf<Test>; 2] {
	[account(100), account(101)]
}

// Returns a full BoundedVec username with suffix, which is what a user would need to sign.
fn test_username_of(int: Vec<u8>, suffix: Vec<u8>) -> Username<Test> {
	let base = b"testusername";
	let mut username = Vec::with_capacity(base.len() + int.len());
	username.extend(base);
	username.extend(int);

	let mut bounded_username = Vec::with_capacity(username.len() + suffix.len() + 1);
	bounded_username.extend(username);
	bounded_username.extend(b".");
	bounded_username.extend(suffix);
	Username::<Test>::try_from(bounded_username).expect("test usernames should fit within bounds")
}

fn infoof_ten() -> IdentityInfo<MaxAdditionalFields> {
	IdentityInfo {
		display: Data::Raw(b"ten".to_vec().try_into().unwrap()),
		legal: Data::Raw(b"The Right Ordinal Ten, Esq.".to_vec().try_into().unwrap()),
		..Default::default()
	}
}

fn infoof_twenty() -> IdentityInfo<MaxAdditionalFields> {
	IdentityInfo {
		display: Data::Raw(b"twenty".to_vec().try_into().unwrap()),
		legal: Data::Raw(b"The Right Ordinal Twenty, Esq.".to_vec().try_into().unwrap()),
		..Default::default()
	}
}

fn id_deposit(id: &IdentityInfo<MaxAdditionalFields>) -> u64 {
	let base_deposit: u64 = <<Test as Config>::BasicDeposit as Get<u64>>::get();
	let byte_deposit: u64 = <<Test as Config>::ByteDeposit as Get<u64>>::get() *
		TryInto::<u64>::try_into(id.encoded_size()).unwrap();
	base_deposit + byte_deposit
}

fn personal_identity_registration(
) -> Registration<u64, MaxRegistrars, IdentityInfo<MaxAdditionalFields>> {
	Registration {
		judgements: alloc::vec![(RegistrarIndex::MAX, Judgement::External)]
			.try_into()
			.expect("judgements must be able to hold at least one element; qed"),
		deposit: 0u32.into(),
		info: IdentityInfo::default(),
	}
}

#[test]
fn identity_fields_repr_works() {
	// `IdentityField` sanity checks.
	assert_eq!(IdentityField::Display as u64, 1 << 0);
	assert_eq!(IdentityField::Legal as u64, 1 << 1);
	assert_eq!(IdentityField::Web as u64, 1 << 2);
	assert_eq!(IdentityField::Riot as u64, 1 << 3);
	assert_eq!(IdentityField::Email as u64, 1 << 4);
	assert_eq!(IdentityField::PgpFingerprint as u64, 1 << 5);
	assert_eq!(IdentityField::Image as u64, 1 << 6);
	assert_eq!(IdentityField::Twitter as u64, 1 << 7);

	let fields = IdentityField::Legal |
		IdentityField::Web |
		IdentityField::Riot |
		IdentityField::PgpFingerprint |
		IdentityField::Twitter;

	assert!(!fields.contains(IdentityField::Display));
	assert!(fields.contains(IdentityField::Legal));
	assert!(fields.contains(IdentityField::Web));
	assert!(fields.contains(IdentityField::Riot));
	assert!(!fields.contains(IdentityField::Email));
	assert!(fields.contains(IdentityField::PgpFingerprint));
	assert!(!fields.contains(IdentityField::Image));
	assert!(fields.contains(IdentityField::Twitter));

	// Ensure that the `u64` representation matches what we expect.
	assert_eq!(
		fields.bits(),
		0b00000000_00000000_00000000_00000000_00000000_00000000_00000000_10101110
	);
}

#[test]
fn editing_subaccounts_should_work() {
	new_test_ext().execute_with(|| {
		let data = |x| Data::Raw(vec![x; 1].try_into().unwrap());
		let [one, two, three, _, ten, twenty, _, _] = accounts();

		assert_noop!(
			Identity::add_sub(RuntimeOrigin::signed(ten.clone()), twenty.clone(), data(1)),
			Error::<Test>::NoIdentity
		);

		let ten_info = infoof_ten();
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(ten.clone()),
			Box::new(ten_info.clone())
		));
		let id_deposit = id_deposit(&ten_info);
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit);

		let sub_deposit: u64 = <<Test as Config>::SubAccountDeposit as Get<u64>>::get();

		// first sub account
		assert_ok!(Identity::add_sub(RuntimeOrigin::signed(ten.clone()), one.clone(), data(1)));
		assert_eq!(SuperOf::<Test>::get(one.clone()), Some((ten.clone(), data(1))));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - sub_deposit);

		// second sub account
		assert_ok!(Identity::add_sub(RuntimeOrigin::signed(ten.clone()), two.clone(), data(2)));
		assert_eq!(SuperOf::<Test>::get(one.clone()), Some((ten.clone(), data(1))));
		assert_eq!(SuperOf::<Test>::get(two.clone()), Some((ten.clone(), data(2))));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - 2 * sub_deposit);

		// third sub account is too many
		assert_noop!(
			Identity::add_sub(RuntimeOrigin::signed(ten.clone()), three.clone(), data(3)),
			Error::<Test>::TooManySubAccounts
		);

		// rename first sub account
		assert_ok!(Identity::rename_sub(RuntimeOrigin::signed(ten.clone()), one.clone(), data(11)));
		System::assert_last_event(tests::RuntimeEvent::Identity(Event::SubIdentityRenamed {
			main: ten.clone(),
			sub: one.clone(),
		}));
		assert_eq!(SuperOf::<Test>::get(one.clone()), Some((ten.clone(), data(11))));
		assert_eq!(SuperOf::<Test>::get(two.clone()), Some((ten.clone(), data(2))));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - 2 * sub_deposit);

		// remove first sub account
		assert_ok!(Identity::remove_sub(RuntimeOrigin::signed(ten.clone()), one.clone()));
		assert_eq!(SuperOf::<Test>::get(one.clone()), None);
		assert_eq!(SuperOf::<Test>::get(two.clone()), Some((ten.clone(), data(2))));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - sub_deposit);

		// add third sub account
		assert_ok!(Identity::add_sub(RuntimeOrigin::signed(ten.clone()), three.clone(), data(3)));
		assert_eq!(SuperOf::<Test>::get(one), None);
		assert_eq!(SuperOf::<Test>::get(two), Some((ten.clone(), data(2))));
		assert_eq!(SuperOf::<Test>::get(three), Some((ten.clone(), data(3))));
		assert_eq!(Balances::free_balance(ten), 1000 - id_deposit - 2 * sub_deposit);
	});
}

#[test]
fn resolving_subaccount_ownership_works() {
	new_test_ext().execute_with(|| {
		let data = |x| Data::Raw(vec![x; 1].try_into().unwrap());
		let [one, _, _, _, ten, twenty, _, _] = accounts();
		let sub_deposit: u64 = <<Test as Config>::SubAccountDeposit as Get<u64>>::get();

		let ten_info = infoof_ten();
		let ten_deposit = id_deposit(&ten_info);
		let twenty_info = infoof_twenty();
		let twenty_deposit = id_deposit(&twenty_info);
		assert_ok!(Identity::set_identity(RuntimeOrigin::signed(ten.clone()), Box::new(ten_info)));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - ten_deposit);
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(twenty.clone()),
			Box::new(twenty_info)
		));
		assert_eq!(Balances::free_balance(twenty.clone()), 1000 - twenty_deposit);

		// 10 claims 1 as a subaccount
		assert_ok!(Identity::add_sub(RuntimeOrigin::signed(ten.clone()), one.clone(), data(1)));
		assert_eq!(Balances::free_balance(one.clone()), 100);
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - ten_deposit - sub_deposit);
		assert_eq!(Balances::reserved_balance(ten.clone()), ten_deposit + sub_deposit);
		// 20 cannot claim 1 now
		assert_noop!(
			Identity::add_sub(RuntimeOrigin::signed(twenty.clone()), one.clone(), data(1)),
			Error::<Test>::AlreadyClaimed
		);
		// 1 wants to be with 20 so it quits from 10
		assert_ok!(Identity::quit_sub(RuntimeOrigin::signed(one.clone())));
		// 1 gets the 10 that 10 paid.
		assert_eq!(Balances::free_balance(one.clone()), 100 + sub_deposit);
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - ten_deposit - sub_deposit);
		assert_eq!(Balances::reserved_balance(ten), ten_deposit);
		// 20 can claim 1 now
		assert_ok!(Identity::add_sub(RuntimeOrigin::signed(twenty), one, data(1)));
	});
}

#[test]
fn trailing_zeros_decodes_into_default_data() {
	let encoded = Data::Raw(b"Hello".to_vec().try_into().unwrap()).encode();
	assert!(<(Data, Data)>::decode(&mut &encoded[..]).is_err());
	let input = &mut &encoded[..];
	let (a, b) = <(Data, Data)>::decode(&mut AppendZerosInput::new(input)).unwrap();
	assert_eq!(a, Data::Raw(b"Hello".to_vec().try_into().unwrap()));
	assert_eq!(b, Data::None);
}

#[test]
fn adding_registrar_invalid_index() {
	new_test_ext().execute_with(|| {
		let [_, _, three, _, _, _, _, _] = accounts();
		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), three.clone()));
		assert_ok!(Identity::set_fee(RuntimeOrigin::signed(three.clone()), 0, 10));
		let fields = IdentityField::Display | IdentityField::Legal;
		assert_noop!(
			Identity::set_fields(RuntimeOrigin::signed(three), 100, fields.bits()),
			Error::<Test>::InvalidIndex
		);
	});
}

#[test]
fn adding_registrar_should_work() {
	new_test_ext().execute_with(|| {
		let [_, _, three, _, _, _, _, _] = accounts();
		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), three.clone()));
		assert_ok!(Identity::set_fee(RuntimeOrigin::signed(three.clone()), 0, 10));
		let fields = IdentityField::Display | IdentityField::Legal;
		assert_ok!(Identity::set_fields(RuntimeOrigin::signed(three.clone()), 0, fields.bits()));
		assert_eq!(
			Registrars::<Test>::get(),
			vec![Some(RegistrarInfo { account: three, fee: 10, fields: fields.bits() })]
		);
	});
}

#[test]
fn amount_of_registrars_is_limited() {
	new_test_ext().execute_with(|| {
		for ii in 1..MaxRegistrars::get() + 1 {
			assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), account_from_u32(ii)));
		}
		let last_registrar = MaxRegistrars::get() + 1;
		assert_noop!(
			Identity::add_registrar(RuntimeOrigin::root(), account_from_u32(last_registrar)),
			Error::<Test>::TooManyRegistrars
		);
	});
}

#[test]
fn registration_should_work() {
	new_test_ext().execute_with(|| {
		let [_, _, three, _, ten, _, _, _] = accounts();
		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), three.clone()));
		assert_ok!(Identity::set_fee(RuntimeOrigin::signed(three.clone()), 0, 10));
		let mut three_fields = infoof_ten();
		three_fields.additional.try_push(Default::default()).unwrap();
		three_fields.additional.try_push(Default::default()).unwrap();
		assert!(three_fields.additional.try_push(Default::default()).is_err());
		let ten_info = infoof_ten();
		let id_deposit = id_deposit(&ten_info);
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(ten.clone()),
			Box::new(ten_info.clone())
		));
		assert_eq!(IdentityOf::<Test>::get(ten.clone()).unwrap().info, ten_info);
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit);
		assert_ok!(Identity::clear_identity(RuntimeOrigin::signed(ten.clone())));
		assert_eq!(Balances::free_balance(ten.clone()), 1000);
		assert_noop!(
			Identity::clear_identity(RuntimeOrigin::signed(ten)),
			Error::<Test>::NoIdentity
		);
	});
}

#[test]
fn uninvited_judgement_should_work() {
	new_test_ext().execute_with(|| {
		let [_, _, three, _, ten, _, _, _] = accounts();
		assert_noop!(
			Identity::provide_judgement(
				RuntimeOrigin::signed(three.clone()),
				0,
				ten.clone(),
				Judgement::Reasonable,
				H256::random()
			),
			Error::<Test>::InvalidIndex
		);

		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), three.clone()));
		assert_noop!(
			Identity::provide_judgement(
				RuntimeOrigin::signed(three.clone()),
				0,
				ten.clone(),
				Judgement::Reasonable,
				H256::random()
			),
			Error::<Test>::InvalidTarget
		);

		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(ten.clone()),
			Box::new(infoof_ten())
		));
		assert_noop!(
			Identity::provide_judgement(
				RuntimeOrigin::signed(three.clone()),
				0,
				ten.clone(),
				Judgement::Reasonable,
				H256::random()
			),
			Error::<Test>::JudgementForDifferentIdentity
		);

		let identity_hash = BlakeTwo256::hash_of(&infoof_ten());

		assert_noop!(
			Identity::provide_judgement(
				RuntimeOrigin::signed(ten.clone()),
				0,
				ten.clone(),
				Judgement::Reasonable,
				identity_hash
			),
			Error::<Test>::InvalidIndex
		);
		assert_noop!(
			Identity::provide_judgement(
				RuntimeOrigin::signed(three.clone()),
				0,
				ten.clone(),
				Judgement::FeePaid(1),
				identity_hash
			),
			Error::<Test>::InvalidJudgement
		);

		assert_ok!(Identity::provide_judgement(
			RuntimeOrigin::signed(three.clone()),
			0,
			ten.clone(),
			Judgement::Reasonable,
			identity_hash
		));
		assert_eq!(
			IdentityOf::<Test>::get(ten).unwrap().judgements,
			vec![(0, Judgement::Reasonable)]
		);
	});
}

#[test]
fn clearing_judgement_should_work() {
	new_test_ext().execute_with(|| {
		let [_, _, three, _, ten, _, _, _] = accounts();
		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), three.clone()));
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(ten.clone()),
			Box::new(infoof_ten())
		));
		assert_ok!(Identity::provide_judgement(
			RuntimeOrigin::signed(three.clone()),
			0,
			ten.clone(),
			Judgement::Reasonable,
			BlakeTwo256::hash_of(&infoof_ten())
		));
		assert_ok!(Identity::clear_identity(RuntimeOrigin::signed(ten.clone())));
		assert_eq!(IdentityOf::<Test>::get(ten), None);
	});
}

#[test]
fn killing_slashing_should_work() {
	new_test_ext().execute_with(|| {
		let [one, _, _, _, ten, _, _, _] = accounts();
		let ten_info = infoof_ten();
		let id_deposit = id_deposit(&ten_info);
		assert_ok!(Identity::set_identity(RuntimeOrigin::signed(ten.clone()), Box::new(ten_info)));
		assert_noop!(Identity::kill_identity(RuntimeOrigin::signed(one), ten.clone()), BadOrigin);
		assert_ok!(Identity::kill_identity(RuntimeOrigin::root(), ten.clone()));
		assert_eq!(IdentityOf::<Test>::get(ten.clone()), None);
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit);
		assert_noop!(
			Identity::kill_identity(RuntimeOrigin::root(), ten),
			Error::<Test>::NoIdentity
		);
	});
}

#[test]
fn setting_subaccounts_should_work() {
	new_test_ext().execute_with(|| {
		let [_, _, _, _, ten, twenty, thirty, forty] = accounts();
		let ten_info = infoof_ten();
		let id_deposit = id_deposit(&ten_info);
		let sub_deposit: u64 = <<Test as Config>::SubAccountDeposit as Get<u64>>::get();
		let mut subs = vec![(twenty.clone(), Data::Raw(vec![40; 1].try_into().unwrap()))];
		assert_noop!(
			Identity::set_subs(RuntimeOrigin::signed(ten.clone()), subs.clone()),
			Error::<Test>::NotFound
		);

		assert_ok!(Identity::set_identity(RuntimeOrigin::signed(ten.clone()), Box::new(ten_info)));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit);
		assert_ok!(Identity::set_subs(RuntimeOrigin::signed(ten.clone()), subs.clone()));

		System::assert_last_event(tests::RuntimeEvent::Identity(Event::SubIdentitiesSet {
			main: ten.clone(),
			number_of_subs: 1,
			new_deposit: sub_deposit,
		}));

		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - sub_deposit);
		assert_eq!(
			SubsOf::<Test>::get(ten.clone()),
			(sub_deposit, vec![twenty.clone()].try_into().unwrap())
		);
		assert_eq!(
			SuperOf::<Test>::get(twenty.clone()),
			Some((ten.clone(), Data::Raw(vec![40; 1].try_into().unwrap())))
		);

		// push another item and re-set it.
		subs.push((thirty.clone(), Data::Raw(vec![50; 1].try_into().unwrap())));
		assert_ok!(Identity::set_subs(RuntimeOrigin::signed(ten.clone()), subs.clone()));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - 2 * sub_deposit);
		assert_eq!(
			SubsOf::<Test>::get(ten.clone()),
			(2 * sub_deposit, vec![twenty.clone(), thirty.clone()].try_into().unwrap())
		);
		assert_eq!(
			SuperOf::<Test>::get(twenty.clone()),
			Some((ten.clone(), Data::Raw(vec![40; 1].try_into().unwrap())))
		);
		assert_eq!(
			SuperOf::<Test>::get(thirty.clone()),
			Some((ten.clone(), Data::Raw(vec![50; 1].try_into().unwrap())))
		);

		// switch out one of the items and re-set.
		subs[0] = (forty.clone(), Data::Raw(vec![60; 1].try_into().unwrap()));
		assert_ok!(Identity::set_subs(RuntimeOrigin::signed(ten.clone()), subs.clone()));
		// no change in the balance
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - 2 * sub_deposit);
		assert_eq!(
			SubsOf::<Test>::get(ten.clone()),
			(2 * sub_deposit, vec![forty.clone(), thirty.clone()].try_into().unwrap())
		);
		assert_eq!(SuperOf::<Test>::get(twenty.clone()), None);
		assert_eq!(
			SuperOf::<Test>::get(thirty.clone()),
			Some((ten.clone(), Data::Raw(vec![50; 1].try_into().unwrap())))
		);
		assert_eq!(
			SuperOf::<Test>::get(forty.clone()),
			Some((ten.clone(), Data::Raw(vec![60; 1].try_into().unwrap())))
		);

		// clear
		assert_ok!(Identity::set_subs(RuntimeOrigin::signed(ten.clone()), vec![]));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit);
		assert_eq!(SubsOf::<Test>::get(ten.clone()), (0, BoundedVec::default()));
		assert_eq!(SuperOf::<Test>::get(thirty.clone()), None);
		assert_eq!(SuperOf::<Test>::get(forty), None);

		subs.push((twenty, Data::Raw(vec![40; 1].try_into().unwrap())));
		assert_noop!(
			Identity::set_subs(RuntimeOrigin::signed(ten), subs.clone()),
			Error::<Test>::TooManySubAccounts
		);
	});
}

#[test]
fn clearing_account_should_remove_subaccounts_and_refund() {
	new_test_ext().execute_with(|| {
		let [_, _, _, _, ten, twenty, _, _] = accounts();
		let ten_info = infoof_ten();
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(ten.clone()),
			Box::new(ten_info.clone())
		));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit(&ten_info));
		assert_ok!(Identity::set_subs(
			RuntimeOrigin::signed(ten.clone()),
			vec![(twenty.clone(), Data::Raw(vec![40; 1].try_into().unwrap()))]
		));
		assert_ok!(Identity::clear_identity(RuntimeOrigin::signed(ten.clone())));
		assert_eq!(Balances::free_balance(ten), 1000);
		assert!(SuperOf::<Test>::get(twenty).is_none());
	});
}

#[test]
fn killing_account_should_remove_subaccounts_and_not_refund() {
	new_test_ext().execute_with(|| {
		let [_, _, _, _, ten, twenty, _, _] = accounts();
		let ten_info = infoof_ten();
		let id_deposit = id_deposit(&ten_info);
		let sub_deposit: u64 = <<Test as Config>::SubAccountDeposit as Get<u64>>::get();
		assert_ok!(Identity::set_identity(RuntimeOrigin::signed(ten.clone()), Box::new(ten_info)));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit);
		assert_ok!(Identity::set_subs(
			RuntimeOrigin::signed(ten.clone()),
			vec![(twenty.clone(), Data::Raw(vec![40; 1].try_into().unwrap()))]
		));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - sub_deposit);
		assert_ok!(Identity::kill_identity(RuntimeOrigin::root(), ten.clone()));
		assert_eq!(Balances::free_balance(ten), 1000 - id_deposit - sub_deposit);
		assert!(SuperOf::<Test>::get(twenty).is_none());
	});
}

#[test]
fn cancelling_requested_judgement_should_work() {
	new_test_ext().execute_with(|| {
		let [_, _, three, _, ten, _, _, _] = accounts();
		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), three.clone()));
		assert_ok!(Identity::set_fee(RuntimeOrigin::signed(three.clone()), 0, 10));
		assert_noop!(
			Identity::cancel_request(RuntimeOrigin::signed(ten.clone()), 0),
			Error::<Test>::NoIdentity
		);
		let ten_info = infoof_ten();
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(ten.clone()),
			Box::new(ten_info.clone())
		));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit(&ten_info));
		assert_ok!(Identity::request_judgement(RuntimeOrigin::signed(ten.clone()), 0, 10));
		assert_ok!(Identity::cancel_request(RuntimeOrigin::signed(ten.clone()), 0));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit(&ten_info));
		assert_noop!(
			Identity::cancel_request(RuntimeOrigin::signed(ten.clone()), 0),
			Error::<Test>::NotFound
		);

		assert_ok!(Identity::provide_judgement(
			RuntimeOrigin::signed(three),
			0,
			ten.clone(),
			Judgement::Reasonable,
			BlakeTwo256::hash_of(&ten_info)
		));
		assert_noop!(
			Identity::cancel_request(RuntimeOrigin::signed(ten), 0),
			Error::<Test>::JudgementGiven
		);
	});
}

#[test]
fn requesting_judgement_should_work() {
	new_test_ext().execute_with(|| {
		let [_, _, three, four, ten, _, _, _] = accounts();
		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), three.clone()));
		assert_ok!(Identity::set_fee(RuntimeOrigin::signed(three.clone()), 0, 10));
		let ten_info = infoof_ten();
		let id_deposit = id_deposit(&ten_info);
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(ten.clone()),
			Box::new(ten_info.clone())
		));
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit);
		assert_noop!(
			Identity::request_judgement(RuntimeOrigin::signed(ten.clone()), 0, 9),
			Error::<Test>::FeeChanged
		);
		assert_ok!(Identity::request_judgement(RuntimeOrigin::signed(ten.clone()), 0, 10));
		// 10 for the judgement request and the deposit for the identity.
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - 10);

		// Re-requesting won't work as we already paid.
		assert_noop!(
			Identity::request_judgement(RuntimeOrigin::signed(ten.clone()), 0, 10),
			Error::<Test>::StickyJudgement
		);
		assert_ok!(Identity::provide_judgement(
			RuntimeOrigin::signed(three.clone()),
			0,
			ten.clone(),
			Judgement::Erroneous,
			BlakeTwo256::hash_of(&ten_info)
		));
		// Registrar got their payment now.
		// 100 initial balance and 10 for the judgement.
		assert_eq!(Balances::free_balance(three.clone()), 100 + 10);

		// Re-requesting still won't work as it's erroneous.
		assert_noop!(
			Identity::request_judgement(RuntimeOrigin::signed(ten.clone()), 0, 10),
			Error::<Test>::StickyJudgement
		);

		// Requesting from a second registrar still works.
		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), four));
		assert_ok!(Identity::request_judgement(RuntimeOrigin::signed(ten.clone()), 1, 10));

		// Re-requesting after the judgement has been reduced works.
		assert_ok!(Identity::provide_judgement(
			RuntimeOrigin::signed(three),
			0,
			ten.clone(),
			Judgement::OutOfDate,
			BlakeTwo256::hash_of(&ten_info)
		));
		assert_ok!(Identity::request_judgement(RuntimeOrigin::signed(ten), 0, 10));
	});
}

#[test]
fn provide_judgement_should_return_judgement_payment_failed_error() {
	new_test_ext().execute_with(|| {
		let [_, _, three, _, ten, _, _, _] = accounts();
		let ten_info = infoof_ten();
		let id_deposit = id_deposit(&ten_info);
		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), three.clone()));
		assert_ok!(Identity::set_fee(RuntimeOrigin::signed(three.clone()), 0, 10));
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(ten.clone()),
			Box::new(ten_info.clone())
		));
		assert_ok!(Identity::request_judgement(RuntimeOrigin::signed(ten.clone()), 0, 10));
		// 10 for the judgement request and the deposit for the identity.
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - 10);

		// This forces judgement payment failed error
		Balances::make_free_balance_be(&three, 0);
		assert_noop!(
			Identity::provide_judgement(
				RuntimeOrigin::signed(three.clone()),
				0,
				ten.clone(),
				Judgement::Erroneous,
				BlakeTwo256::hash_of(&ten_info)
			),
			Error::<Test>::JudgementPaymentFailed
		);
	});
}

#[test]
fn field_deposit_should_work() {
	new_test_ext().execute_with(|| {
		let [_, _, three, _, ten, _, _, _] = accounts();
		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), three.clone()));
		assert_ok!(Identity::set_fee(RuntimeOrigin::signed(three), 0, 10));
		let id = IdentityInfo {
			additional: vec![
				(
					Data::Raw(b"number".to_vec().try_into().unwrap()),
					Data::Raw(10u32.encode().try_into().unwrap()),
				),
				(
					Data::Raw(b"text".to_vec().try_into().unwrap()),
					Data::Raw(b"10".to_vec().try_into().unwrap()),
				),
			]
			.try_into()
			.unwrap(),
			..Default::default()
		};
		let id_deposit = id_deposit(&id);
		assert_ok!(Identity::set_identity(RuntimeOrigin::signed(ten.clone()), Box::new(id)));
		assert_eq!(Balances::free_balance(ten), 1000 - id_deposit);
	});
}

#[test]
fn setting_account_id_should_work() {
	new_test_ext().execute_with(|| {
		let [_, _, three, four, _, _, _, _] = accounts();
		assert_ok!(Identity::add_registrar(RuntimeOrigin::root(), three.clone()));
		// account 4 cannot change the first registrar's identity since it's owned by 3.
		assert_noop!(
			Identity::set_account_id(RuntimeOrigin::signed(four.clone()), 0, three.clone()),
			Error::<Test>::InvalidIndex
		);
		// account 3 can, because that's the registrar's current account.
		assert_ok!(Identity::set_account_id(RuntimeOrigin::signed(three.clone()), 0, four.clone()));
		// account 4 can now, because that's their new ID.
		assert_ok!(Identity::set_account_id(RuntimeOrigin::signed(four), 0, three));
	});
}

#[test]
fn test_has_identity() {
	new_test_ext().execute_with(|| {
		let [_, _, _, _, ten, _, _, _] = accounts();
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(ten.clone()),
			Box::new(infoof_ten())
		));
		assert!(Identity::has_identity(&ten, IdentityField::Display as u64));
		assert!(Identity::has_identity(&ten, IdentityField::Legal as u64));
		assert!(Identity::has_identity(
			&ten,
			IdentityField::Display as u64 | IdentityField::Legal as u64
		));
		assert!(!Identity::has_identity(
			&ten,
			IdentityField::Display as u64 | IdentityField::Legal as u64 | IdentityField::Web as u64
		));
	});
}

#[test]
fn reap_identity_works() {
	new_test_ext().execute_with(|| {
		let [_, _, _, _, ten, twenty, _, _] = accounts();
		let ten_info = infoof_ten();
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(ten.clone()),
			Box::new(ten_info.clone())
		));
		assert_ok!(Identity::set_subs(
			RuntimeOrigin::signed(ten.clone()),
			vec![(twenty.clone(), Data::Raw(vec![40; 1].try_into().unwrap()))]
		));
		// deposit is correct
		let id_deposit = id_deposit(&ten_info);
		let subs_deposit: u64 = <<Test as Config>::SubAccountDeposit as Get<u64>>::get();
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - subs_deposit);
		// reap
		assert_ok!(Identity::reap_identity(&ten));
		// no identity or subs
		assert!(IdentityOf::<Test>::get(ten.clone()).is_none());
		assert!(SuperOf::<Test>::get(twenty).is_none());
		// balance is unreserved
		assert_eq!(Balances::free_balance(ten), 1000);
	});
}

#[test]
fn poke_deposit_works() {
	new_test_ext().execute_with(|| {
		let [_, _, _, _, ten, twenty, _, _] = accounts();
		let ten_info = infoof_ten();
		// Set a custom registration with 0 deposit
		IdentityOf::<Test>::insert::<
			_,
			Registration<u64, MaxRegistrars, IdentityInfo<MaxAdditionalFields>>,
		>(
			&ten,
			Registration {
				judgements: Default::default(),
				deposit: Zero::zero(),
				info: ten_info.clone(),
			},
		);
		assert!(IdentityOf::<Test>::get(ten.clone()).is_some());
		// Set a sub with zero deposit
		SubsOf::<Test>::insert::<_, (u64, BoundedVec<AccountIdOf<Test>, ConstU32<2>>)>(
			&ten,
			(0, vec![twenty.clone()].try_into().unwrap()),
		);
		SuperOf::<Test>::insert(&twenty, (&ten, Data::Raw(vec![1; 1].try_into().unwrap())));
		// Balance is free
		assert_eq!(Balances::free_balance(ten.clone()), 1000);

		// poke
		assert_ok!(Identity::poke_deposit(&ten));

		// free balance reduced correctly
		let id_deposit = id_deposit(&ten_info);
		let subs_deposit: u64 = <<Test as Config>::SubAccountDeposit as Get<u64>>::get();
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit - subs_deposit);
		// new registration deposit is 10
		assert_eq!(
			IdentityOf::<Test>::get(&ten),
			Some(Registration {
				judgements: Default::default(),
				deposit: id_deposit,
				info: infoof_ten()
			},)
		);
		// new subs deposit is 10           vvvvvvvvvvvv
		assert_eq!(SubsOf::<Test>::get(ten), (subs_deposit, vec![twenty].try_into().unwrap()));
	});
}

#[test]
fn poke_deposit_does_not_insert_new_subs_storage() {
	new_test_ext().execute_with(|| {
		let [_, _, _, _, ten, _, _, _] = accounts();
		let ten_info = infoof_ten();
		// Set a custom registration with 0 deposit
		IdentityOf::<Test>::insert::<
			_,
			Registration<u64, MaxRegistrars, IdentityInfo<MaxAdditionalFields>>,
		>(
			&ten,
			Registration {
				judgements: Default::default(),
				deposit: Zero::zero(),
				info: ten_info.clone(),
			},
		);
		assert!(IdentityOf::<Test>::get(ten.clone()).is_some());

		// Balance is free
		assert_eq!(Balances::free_balance(ten.clone()), 1000);

		// poke
		assert_ok!(Identity::poke_deposit(&ten));

		// free balance reduced correctly
		let id_deposit = id_deposit(&ten_info);
		assert_eq!(Balances::free_balance(ten.clone()), 1000 - id_deposit);
		// new registration deposit is 10
		assert_eq!(
			IdentityOf::<Test>::get(&ten),
			Some(Registration {
				judgements: Default::default(),
				deposit: id_deposit,
				info: infoof_ten()
			})
		);
		// No new subs storage item.
		assert!(!SubsOf::<Test>::contains_key(&ten));
	});
}

#[test]
fn adding_and_removing_authorities_should_work() {
	new_test_ext().execute_with(|| {
		let [authority, _] = unfunded_accounts();
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;

		// add
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));
		let suffix: Suffix<Test> = suffix.try_into().unwrap();
		assert_eq!(
			AuthorityOf::<Test>::get(&suffix),
			Some(AuthorityProperties::<AccountIdOf<Test>> {
				account_id: authority.clone(),
				allocation
			})
		);

		// update allocation
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone().into(),
			11u32
		));
		assert_eq!(
			AuthorityOf::<Test>::get(&suffix),
			Some(AuthorityProperties::<AccountIdOf<Test>> {
				account_id: authority.clone(),
				allocation: 11
			})
		);

		// remove
		assert_ok!(Identity::remove_username_authority(
			RuntimeOrigin::root(),
			suffix.clone().into(),
			authority.clone(),
		));
		assert!(AuthorityOf::<Test>::get(&suffix).is_none());
	});
}

#[test]
fn username_minimum_limit_work() {
	new_test_ext().execute_with(|| {
		// set up authority
		let initial_authority_balance = 1000;
		let [authority, _] = unfunded_accounts();
		Balances::make_free_balance_be(&authority, initial_authority_balance);
		let short_suffix: Vec<u8> = b"a".to_vec();
		let allocation: u32 = 10;
		assert_noop!(
			Identity::add_username_authority(
				RuntimeOrigin::root(),
				authority.clone(),
				short_suffix.clone(),
				allocation
			),
			Error::<Test>::InvalidSuffix
		);

		let suffix: Vec<u8> = b"ab".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// set up account
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();

		// set up short username
		let short_username: Username<Test> = b"a.ab".to_vec().try_into().unwrap();
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &short_username[..]).unwrap());

		assert_noop!(
			Identity::set_username_for(
				RuntimeOrigin::signed(authority.clone()),
				who_account.clone(),
				short_username.clone().into(),
				Some(signature),
				true,
			),
			Error::<Test>::InvalidUsername
		);

		// set up username
		let username: Username<Test> = b"ab.ab".to_vec().try_into().unwrap();
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &username[..]).unwrap());

		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who_account.clone(),
			username.clone().into(),
			Some(signature),
			true,
		));

		// username was registered
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(username.clone()));
	});
}

#[test]
fn set_username_with_signature_without_existing_identity_should_work() {
	new_test_ext().execute_with(|| {
		// set up authority
		let initial_authority_balance = 1000;
		let [authority, _] = unfunded_accounts();
		Balances::make_free_balance_be(&authority, initial_authority_balance);
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// set up username
		let username = test_username_of(b"42".to_vec(), suffix.clone());

		// set up user and sign message
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &username[..]).unwrap());

		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who_account.clone(),
			username.clone().into(),
			Some(signature),
			true,
		));

		// Even though user has no balance and no identity, the authority provides the username for
		// free.
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(username.clone()));
		// Lookup from username to account works.
		let expected_user_info =
			UsernameInformation { owner: who_account, provider: Provider::Allocation };
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username),
			Some(expected_user_info)
		);
		// No balance was reserved.
		assert_eq!(Balances::free_balance(&authority), initial_authority_balance);
		// But the allocation decreased.
		assert_eq!(
			AuthorityOf::<Test>::get(Identity::suffix_of_username(&username).unwrap())
				.unwrap()
				.allocation,
			9
		);

		// do the same for a username with a deposit
		let username_deposit: BalanceOf<Test> = <Test as Config>::UsernameDeposit::get();
		// set up username
		let second_username = test_username_of(b"84".to_vec(), suffix.clone());

		// set up user and sign message
		let public = sr25519_generate(1.into(), None);
		let second_who: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let signature =
			MultiSignature::Sr25519(sr25519_sign(1.into(), &public, &second_username[..]).unwrap());
		// don't use the allocation this time
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			second_who.clone(),
			second_username.clone().into(),
			Some(signature),
			false,
		));

		// Even though user has no balance and no identity, the authority placed the deposit for
		// them.
		assert_eq!(UsernameOf::<Test>::get(&second_who), Some(second_username.clone()));
		// Lookup from username to account works.
		let expected_user_info = UsernameInformation {
			owner: second_who,
			provider: Provider::AuthorityDeposit(username_deposit),
		};
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&second_username),
			Some(expected_user_info)
		);
		// The username deposit was reserved.
		assert_eq!(
			Balances::free_balance(&authority),
			initial_authority_balance - username_deposit
		);
		// But the allocation was preserved.
		assert_eq!(
			AuthorityOf::<Test>::get(Identity::suffix_of_username(&second_username).unwrap())
				.unwrap()
				.allocation,
			9
		);
	});
}

#[test]
fn set_username_with_signature_with_existing_identity_should_work() {
	new_test_ext().execute_with(|| {
		// set up authority
		let [authority, _] = unfunded_accounts();
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// set up username
		let username = test_username_of(b"42".to_vec(), suffix);

		// set up user and sign message
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &username[..]).unwrap());

		// Set an identity for who. They need some balance though.
		Balances::make_free_balance_be(&who_account, 1000);
		let ten_info = infoof_ten();
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(who_account.clone()),
			Box::new(ten_info.clone())
		));
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority),
			who_account.clone(),
			username.clone().into(),
			Some(signature),
			true,
		));

		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(username.clone()));
		let expected_user_info =
			UsernameInformation { owner: who_account, provider: Provider::Allocation };
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username),
			Some(expected_user_info)
		);
	});
}

#[test]
fn set_username_through_deposit_with_existing_identity_should_work() {
	new_test_ext().execute_with(|| {
		// set up authority
		let initial_authority_balance = 1000;
		let [authority, _] = unfunded_accounts();
		Balances::make_free_balance_be(&authority, initial_authority_balance);
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// set up username
		let username = test_username_of(b"42".to_vec(), suffix);

		// set up user and sign message
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &username[..]).unwrap());

		// Set an identity for who. They need some balance though.
		Balances::make_free_balance_be(&who_account, 1000);
		let ten_info = infoof_ten();
		let expected_identity_deposit = Identity::calculate_identity_deposit(&ten_info);
		assert_ok!(Identity::set_identity(
			RuntimeOrigin::signed(who_account.clone()),
			Box::new(ten_info.clone())
		));
		assert_eq!(
			expected_identity_deposit,
			IdentityOf::<Test>::get(&who_account).unwrap().deposit
		);
		assert_eq!(Balances::reserved_balance(&who_account), expected_identity_deposit);
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who_account.clone(),
			username.clone().into(),
			Some(signature),
			false,
		));

		let username_deposit: BalanceOf<Test> = <Test as Config>::UsernameDeposit::get();
		// The authority placed the deposit for the username.
		assert_eq!(
			Balances::free_balance(&authority),
			initial_authority_balance - username_deposit
		);
		// No extra balance was reserved from the user for the username.
		assert_eq!(Balances::free_balance(&who_account), 1000 - expected_identity_deposit);
		assert_eq!(Balances::reserved_balance(&who_account), expected_identity_deposit);
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(username.clone()));
		let expected_user_info = UsernameInformation {
			owner: who_account,
			provider: Provider::AuthorityDeposit(username_deposit),
		};
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username),
			Some(expected_user_info)
		);
	});
}

#[test]
fn set_username_with_bytes_signature_should_work() {
	new_test_ext().execute_with(|| {
		// set up authority
		let [authority, _] = unfunded_accounts();
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// set up user
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();

		// set up username
		let username = test_username_of(b"42".to_vec(), suffix);
		let unwrapped_username = username.to_vec();

		// Sign an unwrapped version, as in `username.suffix`.
		let signature_on_unwrapped = MultiSignature::Sr25519(
			sr25519_sign(0.into(), &public, &unwrapped_username[..]).unwrap(),
		);

		// Trivial
		assert_ok!(Identity::validate_signature(
			&unwrapped_username[..],
			&signature_on_unwrapped,
			&who_account
		));

		// Here we are going to wrap the username and suffix in "<Bytes>" and verify that the
		// signature verification still works, but only the username gets set in storage.
		let prehtml = b"<Bytes>";
		let posthtml = b"</Bytes>";
		let mut wrapped_username: Vec<u8> =
			Vec::with_capacity(unwrapped_username.len() + prehtml.len() + posthtml.len());
		wrapped_username.extend(prehtml);
		wrapped_username.extend(unwrapped_username.clone());
		wrapped_username.extend(posthtml);
		let signature_on_wrapped = MultiSignature::Sr25519(
			sr25519_sign(0.into(), &public, &wrapped_username[..]).unwrap(),
		);

		// We want to call `validate_signature` on the *unwrapped* username, but the signature on
		// the *wrapped* data.
		assert_ok!(Identity::validate_signature(
			&unwrapped_username[..],
			&signature_on_wrapped,
			&who_account
		));

		// Make sure it really works in context. Call `set_username_for` with the signature on the
		// wrapped data.
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority),
			who_account.clone(),
			username.clone().into(),
			Some(signature_on_wrapped),
			true,
		));

		// The username in storage should not include `<Bytes>`. As in, it's the original
		// `username_to_sign`.
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(username.clone()));
		// Likewise for the lookup.
		let expected_user_info =
			UsernameInformation { owner: who_account, provider: Provider::Allocation };
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username),
			Some(expected_user_info)
		);
	});
}

#[test]
fn set_username_with_acceptance_should_work() {
	new_test_ext().execute_with(|| {
		// set up authority
		let initial_authority_balance = 1000;
		let [authority, who] = unfunded_accounts();
		Balances::make_free_balance_be(&authority, initial_authority_balance);
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// set up username
		let username = test_username_of(b"101".to_vec(), suffix.clone());
		let now = frame_system::Pallet::<Test>::block_number();
		let expiration = now + <<Test as Config>::PendingUsernameExpiration as Get<u64>>::get();

		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who.clone(),
			username.clone().into(),
			None,
			true,
		));

		// Should be pending
		assert_eq!(
			PendingUsernames::<Test>::get::<&Username<Test>>(&username),
			Some((who.clone(), expiration, Provider::Allocation))
		);

		// Now the user can accept
		assert_ok!(Identity::accept_username(RuntimeOrigin::signed(who.clone()), username.clone()));

		// No more pending
		assert!(PendingUsernames::<Test>::get::<&Username<Test>>(&username).is_none());
		// Check Identity storage
		assert_eq!(UsernameOf::<Test>::get(&who), Some(username.clone()));
		// Check reverse lookup
		let expected_user_info = UsernameInformation { owner: who, provider: Provider::Allocation };
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username),
			Some(expected_user_info)
		);
		assert_eq!(Balances::free_balance(&authority), initial_authority_balance);

		let second_caller = account(99);
		let second_username = test_username_of(b"102".to_vec(), suffix);
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			second_caller.clone(),
			second_username.clone().into(),
			None,
			false,
		));

		// Should be pending
		let username_deposit = <Test as Config>::UsernameDeposit::get();
		assert_eq!(
			PendingUsernames::<Test>::get::<&Username<Test>>(&second_username),
			Some((second_caller.clone(), expiration, Provider::AuthorityDeposit(username_deposit)))
		);
		assert_eq!(
			Balances::free_balance(&authority),
			initial_authority_balance - username_deposit
		);
		// Now the user can accept
		assert_ok!(Identity::accept_username(
			RuntimeOrigin::signed(second_caller.clone()),
			second_username.clone()
		));

		// No more pending
		assert!(PendingUsernames::<Test>::get::<&Username<Test>>(&second_username).is_none());
		// Check Identity storage
		assert_eq!(UsernameOf::<Test>::get(&second_caller), Some(second_username.clone()));
		// Check reverse lookup
		let expected_user_info = UsernameInformation {
			owner: second_caller,
			provider: Provider::AuthorityDeposit(username_deposit),
		};
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&second_username),
			Some(expected_user_info)
		);
		assert_eq!(
			Balances::free_balance(&authority),
			initial_authority_balance - username_deposit
		);
	});
}

#[test]
fn invalid_usernames_should_be_rejected() {
	new_test_ext().execute_with(|| {
		let [authority, who] = unfunded_accounts();
		let allocation: u32 = 10;
		let valid_suffix = b"test".to_vec();
		let invalid_suffixes = [
			b"te.st".to_vec(), // not alphanumeric
			b"su:ffx".to_vec(),
			b"su_ffx".to_vec(),
			b"Suffix".to_vec(),   // capital
			b"suffixes".to_vec(), // too long
		];
		for suffix in invalid_suffixes {
			assert_noop!(
				Identity::add_username_authority(
					RuntimeOrigin::root(),
					authority.clone(),
					suffix.clone(),
					allocation
				),
				Error::<Test>::InvalidSuffix
			);
		}

		// set a valid one now
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			valid_suffix.clone(),
			allocation
		));

		// set up usernames
		let invalid_usernames = [
			b"TestUsername".to_vec(),
			b"test_username".to_vec(),
			b"test-username".to_vec(),
			b"test:username".to_vec(),
			b"test.username".to_vec(),
			b"test@username".to_vec(),
			b"test$username".to_vec(),
			//0         1         2      v With `.test` this makes it too long.
			b"testusernametestusernametest".to_vec(),
		];
		for username in invalid_usernames.into_iter().map(|mut username| {
			username.push(b'.');
			username.extend(valid_suffix.clone());
			username
		}) {
			assert_noop!(
				Identity::set_username_for(
					RuntimeOrigin::signed(authority.clone()),
					who.clone(),
					username.clone(),
					None,
					true,
				),
				Error::<Test>::InvalidUsername
			);
		}

		// valid one works
		let mut valid_username = b"testusernametestusernametes".to_vec();
		valid_username.push(b'.');
		valid_username.extend(valid_suffix);
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority),
			who,
			valid_username,
			None,
			true,
		));
	});
}

#[test]
fn authorities_should_run_out_of_allocation() {
	new_test_ext().execute_with(|| {
		// set up authority
		let [authority, _] = unfunded_accounts();
		let [pi, e, c, _, _, _, _, _] = accounts();
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 2;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			pi,
			b"username314159.test".to_vec(),
			None,
			true,
		));
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			e,
			b"username271828.test".to_vec(),
			None,
			true
		));
		assert_noop!(
			Identity::set_username_for(
				RuntimeOrigin::signed(authority.clone()),
				c,
				b"username299792458.test".to_vec(),
				None,
				true,
			),
			Error::<Test>::NoAllocation
		);
	});
}

#[test]
fn setting_primary_should_work() {
	new_test_ext().execute_with(|| {
		// set up authority
		let [authority, _] = unfunded_accounts();
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// set up user
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();

		// set up username
		let first_username = test_username_of(b"42".to_vec(), suffix.clone());
		let first_signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &first_username[..]).unwrap());

		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who_account.clone(),
			first_username.clone().into(),
			Some(first_signature),
			true
		));

		// First username set as primary.
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(first_username.clone()));

		// set up username
		let second_username = test_username_of(b"101".to_vec(), suffix);
		let second_signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &second_username[..]).unwrap());

		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority),
			who_account.clone(),
			second_username.clone().into(),
			Some(second_signature),
			true,
		));

		// The primary is still the first username.
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(first_username.clone()));

		// Lookup from both works.
		let expected_user_info =
			UsernameInformation { owner: who_account.clone(), provider: Provider::Allocation };
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&first_username),
			Some(expected_user_info.clone())
		);
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&second_username),
			Some(expected_user_info.clone())
		);

		assert_ok!(Identity::set_primary_username(
			RuntimeOrigin::signed(who_account.clone()),
			second_username.clone()
		));

		// The primary is now the second username.
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(second_username.clone()));

		// Lookup from both still works.
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&first_username),
			Some(expected_user_info.clone())
		);
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&second_username),
			Some(expected_user_info)
		);
	});
}

#[test]
fn must_own_primary() {
	new_test_ext().execute_with(|| {
		// set up authority
		let [authority, _] = unfunded_accounts();
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// Set up first user ("pi") and a username.
		let pi_public = sr25519_generate(0.into(), None);
		let pi_account: AccountIdOf<Test> = MultiSigner::Sr25519(pi_public).into_account();
		let pi_username = test_username_of(b"username314159".to_vec(), suffix.clone());
		let pi_signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &pi_public, &pi_username[..]).unwrap());
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			pi_account.clone(),
			pi_username.clone().into(),
			Some(pi_signature),
			true,
		));

		// Set up second user ("e") and a username.
		let e_public = sr25519_generate(1.into(), None);
		let e_account: AccountIdOf<Test> = MultiSigner::Sr25519(e_public).into_account();
		let e_username = test_username_of(b"username271828".to_vec(), suffix.clone());
		let e_signature =
			MultiSignature::Sr25519(sr25519_sign(1.into(), &e_public, &e_username[..]).unwrap());
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			e_account.clone(),
			e_username.clone().into(),
			Some(e_signature),
			true
		));

		// Ensure that both users have their usernames.
		let expected_pi_info =
			UsernameInformation { owner: pi_account.clone(), provider: Provider::Allocation };
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&pi_username),
			Some(expected_pi_info)
		);
		let expected_e_info =
			UsernameInformation { owner: e_account.clone(), provider: Provider::Allocation };
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&e_username),
			Some(expected_e_info)
		);

		// Cannot set primary to a username that does not exist.
		let c_username = test_username_of(b"speedoflight".to_vec(), suffix.clone());
		assert_err!(
			Identity::set_primary_username(RuntimeOrigin::signed(pi_account.clone()), c_username),
			Error::<Test>::NoUsername
		);

		// Cannot take someone else's username as your primary.
		assert_err!(
			Identity::set_primary_username(RuntimeOrigin::signed(pi_account.clone()), e_username),
			Error::<Test>::InvalidUsername
		);
	});
}

#[test]
fn unaccepted_usernames_through_grant_should_expire() {
	new_test_ext().execute_with(|| {
		// set up authority
		let initial_authority_balance = 1000;
		let [authority, who] = unfunded_accounts();
		Balances::make_free_balance_be(&authority, initial_authority_balance);
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// set up username
		let username = test_username_of(b"101".to_vec(), suffix.clone());
		let now = frame_system::Pallet::<Test>::block_number();
		let expiration = now + <<Test as Config>::PendingUsernameExpiration as Get<u64>>::get();

		let suffix: Suffix<Test> = suffix.try_into().unwrap();

		assert_eq!(AuthorityOf::<Test>::get(&suffix).unwrap().allocation, 10);
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who.clone(),
			username.clone().into(),
			None,
			true,
		));
		assert_eq!(Balances::free_balance(&authority), initial_authority_balance);
		assert_eq!(AuthorityOf::<Test>::get(&suffix).unwrap().allocation, 9);

		// Should be pending
		assert_eq!(
			PendingUsernames::<Test>::get::<&Username<Test>>(&username),
			Some((who.clone(), expiration, Provider::Allocation))
		);

		run_to_block(now + expiration - 1);

		// Cannot be removed
		assert_noop!(
			Identity::remove_expired_approval(RuntimeOrigin::signed(account(1)), username.clone()),
			Error::<Test>::NotExpired
		);

		run_to_block(now + expiration);

		// Anyone can remove
		assert_ok!(Identity::remove_expired_approval(
			RuntimeOrigin::signed(account(1)),
			username.clone()
		));
		assert_eq!(Balances::free_balance(&authority), initial_authority_balance);
		// Allocation wasn't refunded
		assert_eq!(AuthorityOf::<Test>::get(&suffix).unwrap().allocation, 9);

		// No more pending
		assert!(PendingUsernames::<Test>::get::<&Username<Test>>(&username).is_none());
	});
}

#[test]
fn unaccepted_usernames_through_deposit_should_expire() {
	new_test_ext().execute_with(|| {
		// set up authority
		let initial_authority_balance = 1000;
		let [authority, who] = unfunded_accounts();
		Balances::make_free_balance_be(&authority, initial_authority_balance);
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// set up username
		let username = test_username_of(b"101".to_vec(), suffix.clone());
		let now = frame_system::Pallet::<Test>::block_number();
		let expiration = now + <<Test as Config>::PendingUsernameExpiration as Get<u64>>::get();

		let suffix: Suffix<Test> = suffix.try_into().unwrap();
		let username_deposit: BalanceOf<Test> = <Test as Config>::UsernameDeposit::get();

		assert_eq!(AuthorityOf::<Test>::get(&suffix).unwrap().allocation, 10);
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who.clone(),
			username.clone().into(),
			None,
			false,
		));
		assert_eq!(
			Balances::free_balance(&authority),
			initial_authority_balance - username_deposit
		);
		assert_eq!(AuthorityOf::<Test>::get(&suffix).unwrap().allocation, 10);

		// Should be pending
		assert_eq!(
			PendingUsernames::<Test>::get::<&Username<Test>>(&username),
			Some((who.clone(), expiration, Provider::AuthorityDeposit(username_deposit)))
		);

		run_to_block(now + expiration - 1);

		// Cannot be removed
		assert_noop!(
			Identity::remove_expired_approval(RuntimeOrigin::signed(account(1)), username.clone()),
			Error::<Test>::NotExpired
		);

		run_to_block(now + expiration);

		// Anyone can remove
		assert_eq!(
			Balances::free_balance(&authority),
			initial_authority_balance - username_deposit
		);
		assert_eq!(Balances::reserved_balance(&authority), username_deposit);
		assert_ok!(Identity::remove_expired_approval(
			RuntimeOrigin::signed(account(1)),
			username.clone()
		));
		// Deposit was refunded
		assert_eq!(Balances::free_balance(&authority), initial_authority_balance);
		// Allocation wasn't refunded
		assert_eq!(AuthorityOf::<Test>::get(&suffix).unwrap().allocation, 10);

		// No more pending
		assert!(PendingUsernames::<Test>::get::<&Username<Test>>(&username).is_none());
	});
}

#[test]
fn kill_username_should_work() {
	new_test_ext().execute_with(|| {
		let initial_authority_balance = 10000;
		// set up first authority
		let authority = account(100);
		Balances::make_free_balance_be(&authority, initial_authority_balance);
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		let second_authority = account(200);
		Balances::make_free_balance_be(&second_authority, initial_authority_balance);
		let second_suffix: Vec<u8> = b"abc".to_vec();
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			second_authority.clone(),
			second_suffix.clone(),
			allocation
		));

		let username_deposit = <Test as Config>::UsernameDeposit::get();

		// set up username
		let username = test_username_of(b"42".to_vec(), suffix.clone());

		// set up user and sign message
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &username[..]).unwrap());

		// Set an identity for who. They need some balance though.
		Balances::make_free_balance_be(&who_account, 1000);
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who_account.clone(),
			username.clone().into(),
			Some(signature),
			false
		));
		assert_eq!(
			Balances::free_balance(authority.clone()),
			initial_authority_balance - username_deposit
		);

		// Now they set up a second username.
		let username_two = test_username_of(b"43".to_vec(), suffix.clone());

		// set up user and sign message
		let signature_two =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &username_two[..]).unwrap());

		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who_account.clone(),
			username_two.clone().into(),
			Some(signature_two),
			false
		));
		assert_eq!(
			Balances::free_balance(authority.clone()),
			initial_authority_balance - 2 * username_deposit
		);

		// Now they set up a third username with another authority.
		let username_three = test_username_of(b"42".to_vec(), second_suffix.clone());

		// set up user and sign message
		let signature_three =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &username_three[..]).unwrap());

		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(second_authority.clone()),
			who_account.clone(),
			username_three.clone().into(),
			Some(signature_three),
			true
		));
		assert_eq!(
			Balances::free_balance(authority.clone()),
			initial_authority_balance - 2 * username_deposit
		);
		assert_eq!(Balances::free_balance(second_authority.clone()), initial_authority_balance);

		// The primary should still be the first one.
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(username.clone()));

		// But both usernames should look up the account.
		let expected_user_info = UsernameInformation {
			owner: who_account.clone(),
			provider: Provider::AuthorityDeposit(username_deposit),
		};
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username),
			Some(expected_user_info.clone())
		);
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username_two),
			Some(expected_user_info.clone())
		);

		// Regular accounts can't kill a username, not even the authority that granted it.
		assert_noop!(
			Identity::kill_username(RuntimeOrigin::signed(authority.clone()), username.clone()),
			BadOrigin
		);

		// Can't kill a username that doesn't exist.
		assert_noop!(
			Identity::kill_username(
				RuntimeOrigin::root(),
				test_username_of(b"999".to_vec(), suffix.clone())
			),
			Error::<Test>::NoUsername
		);

		// Unbind the second username.
		assert_ok!(Identity::unbind_username(
			RuntimeOrigin::signed(authority.clone()),
			username_two.clone()
		));

		// Kill the second username.
		assert_ok!(Identity::kill_username(RuntimeOrigin::root(), username_two.clone()));

		// The reverse lookup of the primary is gone.
		assert!(UsernameInfoOf::<Test>::get::<&Username<Test>>(&username_two).is_none());
		// The unbinding map entry is gone.
		assert!(UnbindingUsernames::<Test>::get::<&Username<Test>>(&username).is_none());
		// The authority's deposit was slashed.
		assert_eq!(Balances::reserved_balance(authority.clone()), username_deposit);

		// But the reverse lookup of the primary is still there
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username),
			Some(expected_user_info)
		);
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(username.clone()));
		assert!(UsernameInfoOf::<Test>::contains_key(&username_three));

		// Kill the first, primary username.
		assert_ok!(Identity::kill_username(RuntimeOrigin::root(), username.clone()));

		// The reverse lookup of the primary is gone.
		assert!(UsernameInfoOf::<Test>::get::<&Username<Test>>(&username).is_none());
		assert!(!UsernameOf::<Test>::contains_key(&who_account));
		// The authority's deposit was slashed.
		assert_eq!(Balances::reserved_balance(authority.clone()), 0);

		// But the reverse lookup of the third and final username is still there
		let expected_user_info =
			UsernameInformation { owner: who_account.clone(), provider: Provider::Allocation };
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username_three),
			Some(expected_user_info)
		);

		// Kill the third and last username.
		assert_ok!(Identity::kill_username(RuntimeOrigin::root(), username_three.clone()));
		// Everything is gone.
		assert!(!UsernameInfoOf::<Test>::contains_key(&username_three));
	});
}

#[test]
fn unbind_and_remove_username_should_work() {
	new_test_ext().execute_with(|| {
		let initial_authority_balance = 10000;
		// Set up authority.
		let authority = account(100);
		Balances::make_free_balance_be(&authority, initial_authority_balance);
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		let username_deposit = <Test as Config>::UsernameDeposit::get();

		// Set up username.
		let username = test_username_of(b"42".to_vec(), suffix.clone());

		// Set up user and sign message.
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &username[..]).unwrap());

		// Set an identity for who. They need some balance though.
		Balances::make_free_balance_be(&who_account, 1000);
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who_account.clone(),
			username.clone().into(),
			Some(signature),
			false
		));
		assert_eq!(
			Balances::free_balance(authority.clone()),
			initial_authority_balance - username_deposit
		);

		// Now they set up a second username.
		let username_two = test_username_of(b"43".to_vec(), suffix.clone());

		// Set up user and sign message.
		let signature_two =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &username_two[..]).unwrap());

		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who_account.clone(),
			username_two.clone().into(),
			Some(signature_two),
			true
		));
		// Second one is free.
		assert_eq!(
			Balances::free_balance(authority.clone()),
			initial_authority_balance - username_deposit
		);

		// The primary should still be the first one.
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(username.clone()));

		// But both usernames should look up the account.
		let expected_user_info = UsernameInformation {
			owner: who_account.clone(),
			provider: Provider::AuthorityDeposit(username_deposit),
		};
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username),
			Some(expected_user_info.clone())
		);
		let expected_user_info =
			UsernameInformation { owner: who_account.clone(), provider: Provider::Allocation };
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username_two),
			Some(expected_user_info.clone())
		);

		// Regular accounts can't kill a username, not even the authority that granted it.
		assert_noop!(
			Identity::kill_username(RuntimeOrigin::signed(authority.clone()), username.clone()),
			BadOrigin
		);

		// Can't unbind a username that doesn't exist.
		let dummy_suffix = b"abc".to_vec();
		let dummy_username = test_username_of(b"999".to_vec(), dummy_suffix.clone());
		let dummy_authority = account(78);
		assert_noop!(
			Identity::unbind_username(
				RuntimeOrigin::signed(dummy_authority.clone()),
				dummy_username.clone()
			),
			Error::<Test>::NoUsername
		);

		let dummy_suffix: Suffix<Test> = dummy_suffix.try_into().unwrap();
		// Only the authority that granted the username can unbind it.
		UsernameInfoOf::<Test>::insert(
			dummy_username.clone(),
			UsernameInformation { owner: who_account.clone(), provider: Provider::Allocation },
		);
		assert_noop!(
			Identity::unbind_username(
				RuntimeOrigin::signed(dummy_authority.clone()),
				dummy_username.clone()
			),
			Error::<Test>::NotUsernameAuthority
		);
		// Simulate a dummy authority.
		AuthorityOf::<Test>::insert(
			dummy_suffix.clone(),
			AuthorityProperties { account_id: dummy_authority.clone(), allocation: 10 },
		);
		// But try to remove the dummy username as a different authority, not the one that
		// originally granted the username.
		assert_noop!(
			Identity::unbind_username(
				RuntimeOrigin::signed(authority.clone()),
				dummy_username.clone()
			),
			Error::<Test>::NotUsernameAuthority
		);
		// Clean up storage.
		let _ = UsernameInfoOf::<Test>::take(dummy_username.clone());
		let _ = AuthorityOf::<Test>::take(dummy_suffix);

		// We can successfully unbind the username as the authority that granted it.
		assert_ok!(Identity::unbind_username(
			RuntimeOrigin::signed(authority.clone()),
			username_two.clone()
		));
		let grace_period: BlockNumberFor<Test> = <Test as Config>::UsernameGracePeriod::get();
		let now = 1;
		assert_eq!(System::block_number(), now);
		let expected_grace_period_expiry: BlockNumberFor<Test> = now + grace_period;
		assert_eq!(
			UnbindingUsernames::<Test>::get(&username_two),
			Some(expected_grace_period_expiry)
		);

		// Still in the grace period.
		assert_noop!(
			Identity::remove_username(RuntimeOrigin::signed(account(0)), username_two.clone()),
			Error::<Test>::TooEarly
		);

		// Advance the block number to simulate the grace period passing.
		System::set_block_number(expected_grace_period_expiry);

		let suffix: Suffix<Test> = suffix.try_into().unwrap();
		// We can now remove the username from any account.
		assert_ok!(Identity::remove_username(
			RuntimeOrigin::signed(account(0)),
			username_two.clone()
		));
		// The username is gone.
		assert!(!UnbindingUsernames::<Test>::contains_key(&username_two));
		assert!(!UsernameInfoOf::<Test>::contains_key(&username_two));
		// Primary username was preserved.
		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(username.clone()));
		// The username was granted through a governance allocation, so no deposit was released.
		assert_eq!(
			Balances::free_balance(authority.clone()),
			initial_authority_balance - username_deposit
		);
		// Allocation wasn't refunded.
		assert_eq!(AuthorityOf::<Test>::get(&suffix).unwrap().allocation, 9);

		// Unbind the first username as well.
		assert_ok!(Identity::unbind_username(
			RuntimeOrigin::signed(authority.clone()),
			username.clone()
		));
		let now: BlockNumberFor<Test> = expected_grace_period_expiry;
		assert_eq!(System::block_number(), now);
		let expected_grace_period_expiry: BlockNumberFor<Test> = now + grace_period;
		assert_eq!(UnbindingUsernames::<Test>::get(&username), Some(expected_grace_period_expiry));
		// Advance the block number to simulate the grace period passing.
		System::set_block_number(expected_grace_period_expiry);
		// We can now remove the username from any account.
		assert_ok!(Identity::remove_username(RuntimeOrigin::signed(account(0)), username.clone()));
		// The username is gone.
		assert!(!UnbindingUsernames::<Test>::contains_key(&username));
		assert!(!UsernameInfoOf::<Test>::contains_key(&username));
		// Primary username was also removed.
		assert!(!UsernameOf::<Test>::contains_key(&who_account));
		// The username deposit was released.
		assert_eq!(Balances::free_balance(authority.clone()), initial_authority_balance);
		// Allocation didn't change.
		assert_eq!(AuthorityOf::<Test>::get(&suffix).unwrap().allocation, 9);
	});
}

#[test]
#[should_panic]
fn unbind_dangling_username_defensive_should_panic() {
	new_test_ext().execute_with(|| {
		let initial_authority_balance = 10000;
		// Set up authority.
		let authority = account(100);
		Balances::make_free_balance_be(&authority, initial_authority_balance);
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		let username_deposit: BalanceOf<Test> = <Test as Config>::UsernameDeposit::get();

		// Set up username.
		let username = test_username_of(b"42".to_vec(), suffix.clone());

		// Set up user and sign message.
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &username[..]).unwrap());

		// Set an identity for who. They need some balance though.
		Balances::make_free_balance_be(&who_account, 1000);
		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who_account.clone(),
			username.clone().into(),
			Some(signature),
			false
		));
		assert_eq!(
			Balances::free_balance(authority.clone()),
			initial_authority_balance - username_deposit
		);

		// We can successfully unbind the username as the authority that granted it.
		assert_ok!(Identity::unbind_username(
			RuntimeOrigin::signed(authority.clone()),
			username.clone()
		));
		assert_eq!(System::block_number(), 1);
		assert_eq!(UnbindingUsernames::<Test>::get(&username), Some(1));

		// Still in the grace period.
		assert_noop!(
			Identity::remove_username(RuntimeOrigin::signed(account(0)), username.clone()),
			Error::<Test>::TooEarly
		);

		// Advance the block number to simulate the grace period passing.
		System::set_block_number(3);

		// Simulate a dangling entry in the unbinding map without an actual username registered.
		UsernameInfoOf::<Test>::remove(&username);
		UsernameOf::<Test>::remove(&who_account);
		assert_noop!(
			Identity::remove_username(RuntimeOrigin::signed(account(0)), username.clone()),
			Error::<Test>::NoUsername
		);
	});
}

#[test]
fn set_personal_identity_works() {
	new_test_ext().execute_with(|| {
		// set up username
		let username: Username<Test> = b"42".to_vec().try_into().unwrap();

		// set up user and sign message
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &alias[..]).unwrap());

		assert_ok!(Identity::set_personal_identity(
			RuntimeOrigin::signed(who_account.clone()),
			who_account.clone(),
			signature.clone(),
			username.clone(),
		));

		assert_eq!(UsernameOf::<Test>::get(&who_account), Some(username.clone()));
		let expected_user_info =
			UsernameInformation { owner: who_account.clone(), provider: Provider::System };
		assert_eq!(
			UsernameInfoOf::<Test>::get::<&Username<Test>>(&username),
			Some(expected_user_info)
		);
		let registration = personal_identity_registration();
		assert_eq!(IdentityOf::<Test>::get(&who_account), Some(registration));
		let personal_metadata = PersonalIdentity::new(who_account.clone());
		assert_eq!(PersonIdentities::<Test>::get(alias), Some(personal_metadata));
		assert_eq!(AccountToAlias::<Test>::get(&who_account), Some(alias));
		// No balance was reserved.
		assert!(Balances::free_balance(&who_account).is_zero());
	});
}

#[test]
fn set_personal_identity_with_existing_entry_fails() {
	new_test_ext().execute_with(|| {
		// set up username
		let username: Username<Test> = b"42".to_vec().try_into().unwrap();

		// set up user and sign message
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &alias[..]).unwrap());

		IdentityOf::<Test>::insert(&who_account, personal_identity_registration());
		assert_noop!(
			Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account.clone(),
				signature.clone(),
				username.clone(),
			),
			Error::<Test>::AlreadyRegistered
		);
		IdentityOf::<Test>::take(&who_account);

		PersonIdentities::<Test>::insert(alias, PersonalIdentity::new(who_account.clone()));
		assert_noop!(
			Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account.clone(),
				signature.clone(),
				username.clone(),
			),
			Error::<Test>::AlreadyRegistered
		);
		PersonIdentities::<Test>::take(alias);

		UsernameOf::<Test>::insert(&who_account, &username);
		assert_noop!(
			Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account.clone(),
				signature.clone(),
				username.clone(),
			),
			Error::<Test>::AlreadyRegistered
		);
		UsernameOf::<Test>::take(&who_account);

		let username_info =
			UsernameInformation { owner: who_account.clone(), provider: Provider::new_permanent() };
		UsernameInfoOf::<Test>::insert(&username, username_info);
		assert_noop!(
			Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account.clone(),
				signature.clone(),
				username.clone(),
			),
			Error::<Test>::AlreadyRegistered
		);
		UsernameInfoOf::<Test>::take(&username);

		AccountToAlias::<Test>::insert(&who_account, alias);
		assert_noop!(
			Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account.clone(),
				signature.clone(),
				username.clone(),
			),
			Error::<Test>::AlreadyRegistered
		);
		AccountToAlias::<Test>::take(&who_account);
	});
}

#[test]
fn set_personal_identity_invalid_username() {
	new_test_ext().execute_with(|| {
		// set up user and sign message
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &alias[..]).unwrap());

		let username_with_suffix: Username<Test> = b"42.dot".to_vec().try_into().unwrap();
		assert_noop!(
			Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account.clone(),
				signature.clone(),
				username_with_suffix,
			),
			Error::<Test>::InvalidUsername
		);

		let username_with_uppercase: Username<Test> = b"DOT42".to_vec().try_into().unwrap();
		assert_noop!(
			Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account.clone(),
				signature.clone(),
				username_with_uppercase,
			),
			Error::<Test>::InvalidUsername
		);

		let empty_username: Username<Test> = b"".to_vec().try_into().unwrap();
		assert_noop!(
			Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account,
				signature,
				empty_username,
			),
			Error::<Test>::InvalidUsername
		);
	});
}

#[test]
fn set_personal_identity_invalid_signature() {
	new_test_ext().execute_with(|| {
		// set up username
		let username: Username<Test> = b"42".to_vec().try_into().unwrap();

		// set up user and sign message
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, b"bogus payload").unwrap());

		assert_noop!(
			Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account,
				signature,
				username,
			),
			Error::<Test>::InvalidSignature
		);
	});
}

#[test]
fn judge_personal_evidence_works() {
	new_test_ext().execute_with(|| {
		// set up username
		let username: Username<Test> = b"42".to_vec().try_into().unwrap();

		// set up user and sign message
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &alias[..]).unwrap());

		assert_ok!(Identity::set_personal_identity(
			RuntimeOrigin::signed(who_account.clone()),
			who_account.clone(),
			signature.clone(),
			username.clone(),
		));

		let gh_credential = Social::Github { username: b"github".to_vec().try_into().unwrap() };
		assert_ok!(Identity::submit_personal_credential_evidence(
			RuntimeOrigin::signed(who_account.clone()),
			gh_credential.clone()
		));

		let expected_pending_judgements: BoundedVec<(Social, OracleTicketOf<Test>), MaxRegistrars> =
			vec![(gh_credential.clone(), alias)].try_into().unwrap();
		assert_eq!(
			PersonIdentities::<Test>::get(alias).unwrap().pending_judgements,
			expected_pending_judgements
		);

		let tw_credential = Social::Twitter { username: b"twitter".to_vec().try_into().unwrap() };
		assert_ok!(Identity::submit_personal_credential_evidence(
			RuntimeOrigin::signed(who_account.clone()),
			tw_credential.clone()
		));

		let expected_pending_judgements: BoundedVec<(Social, OracleTicketOf<Test>), MaxRegistrars> =
			vec![(gh_credential, alias), (tw_credential.clone(), alias)].try_into().unwrap();
		assert_eq!(
			PersonIdentities::<Test>::get(alias).unwrap().pending_judgements,
			expected_pending_judgements
		);
		assert_eq!(IdentityOf::<Test>::get(&who_account).unwrap().info, IdentityInfo::default());

		let mut ctx: JudgementContext = [0u8; 64].to_vec().try_into().unwrap();
		(ctx[..32]).copy_from_slice(&alias[..]);
		assert_ok!(Identity::personal_credential_judged(
			RuntimeOrigin::root(),
			alias,
			ctx.clone(),
			OracleJudgement::Truth(Truth::True)
		));
		let expected_pending_judgements: BoundedVec<(Social, OracleTicketOf<Test>), MaxRegistrars> =
			vec![(tw_credential, alias)].try_into().unwrap();
		assert_eq!(
			PersonIdentities::<Test>::get(alias).unwrap().pending_judgements,
			expected_pending_judgements
		);
		assert!(IdentityOf::<Test>::get(&who_account).unwrap().info.additional.iter().any(
			|(platform, user)| {
				if let (Data::Raw(platform), Data::Raw(user)) = (platform, user) {
					&platform[..] == b"Github" && &user[..] == b"github"
				} else {
					false
				}
			}
		));

		assert_ok!(Identity::personal_credential_judged(
			RuntimeOrigin::root(),
			alias,
			ctx.clone(),
			OracleJudgement::Truth(Truth::True)
		));
		assert!(PersonIdentities::<Test>::get(alias).unwrap().pending_judgements.is_empty());
		let mut expected_info = IdentityInfo {
			twitter: Data::Raw(b"twitter".to_vec().try_into().unwrap()),
			..Default::default()
		};
		expected_info
			.additional
			.try_push((
				Data::Raw(b"Github".to_vec().try_into().unwrap()),
				Data::Raw(b"github".to_vec().try_into().unwrap()),
			))
			.unwrap();
		assert_eq!(IdentityOf::<Test>::get(&who_account).unwrap().info, expected_info);
	});
}

#[test]
fn judged_callback_works() {
	new_test_ext().execute_with(|| {
		// set up user
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];

		let mut ctx: JudgementContext = [0u8; 64].to_vec().try_into().unwrap();
		(ctx[..32]).copy_from_slice(&alias[..]);
		assert_noop!(
			Identity::personal_credential_judged(
				RuntimeOrigin::root(),
				alias,
				ctx.clone(),
				OracleJudgement::Truth(Truth::True)
			),
			Error::<Test>::NotFound
		);

		PersonIdentities::<Test>::insert(
			alias,
			PersonalIdentity {
				account: who_account.clone(),
				pending_judgements: Default::default(),
				banned: false,
				username_last_reported_at: None,
			},
		);

		assert_noop!(
			Identity::personal_credential_judged(
				RuntimeOrigin::root(),
				alias,
				ctx.clone(),
				OracleJudgement::Truth(Truth::True)
			),
			Error::<Test>::UnexpectedJudgement
		);

		let gh_credential = Social::Github { username: b"github".to_vec().try_into().unwrap() };
		PersonIdentities::<Test>::mutate(alias, |maybe_id| {
			let id = maybe_id.as_mut().unwrap();
			id.pending_judgements.try_push((gh_credential, alias)).unwrap();
		});

		assert_noop!(
			Identity::personal_credential_judged(
				RuntimeOrigin::root(),
				alias,
				ctx.clone(),
				OracleJudgement::Truth(Truth::True)
			),
			Error::<Test>::NoIdentity
		);

		IdentityOf::<Test>::insert(
			&who_account,
			Registration {
				judgements: vec![(RegistrarIndex::MAX, Judgement::External)].try_into().unwrap(),
				deposit: 0u32.into(),
				info: Default::default(),
			},
		);

		assert_ok!(Identity::personal_credential_judged(
			RuntimeOrigin::root(),
			alias,
			ctx,
			OracleJudgement::Truth(Truth::True)
		));
	});
}

#[test]
fn clear_personal_evidence_works() {
	new_test_ext().execute_with(|| {
		// set up username
		let username: Username<Test> = b"42".to_vec().try_into().unwrap();

		// set up user
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];

		assert_noop!(
			Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())),
			Error::<Test>::NotFound
		);

		PersonIdentities::<Test>::insert(
			alias,
			PersonalIdentity {
				account: who_account.clone(),
				pending_judgements: Default::default(),
				banned: false,
				username_last_reported_at: None,
			},
		);
		assert_noop!(
			Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())),
			Error::<Test>::NotFound
		);

		AccountToAlias::<Test>::insert(&who_account, alias);
		assert_noop!(
			Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())),
			Error::<Test>::NoIdentity
		);

		IdentityOf::<Test>::insert(
			&who_account,
			Registration {
				judgements: vec![(RegistrarIndex::MAX, Judgement::External)].try_into().unwrap(),
				deposit: 0u32.into(),
				info: Default::default(),
			},
		);
		assert_noop!(
			Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())),
			Error::<Test>::NoUsername
		);

		UsernameOf::<Test>::insert(&who_account, &username);
		assert_noop!(
			Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())),
			Error::<Test>::NoUsername
		);

		UsernameInfoOf::<Test>::insert(
			&username,
			UsernameInformation {
				owner: who_account.clone(),
				provider: Provider::new_with_allocation(),
			},
		);
		assert_noop!(
			Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())),
			Error::<Test>::InvalidUsername
		);

		UsernameInfoOf::<Test>::insert(
			&username,
			UsernameInformation { owner: who_account.clone(), provider: Provider::new_permanent() },
		);
		assert_noop!(
			Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())),
			pallet_balances::Error::<Test>::InsufficientBalance
		);

		let removal_penalty: <Test as pallet_balances::Config>::Balance =
			<Test as pallet_identity::Config>::CredentialRemovalPenalty::get();
		Balances::make_free_balance_be(&who_account, removal_penalty.saturating_sub(1));
		assert_noop!(
			Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())),
			pallet_balances::Error::<Test>::InsufficientBalance
		);

		Balances::make_free_balance_be(&who_account, removal_penalty);
		assert_ok!(Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())));

		assert!(!PersonIdentities::<Test>::contains_key(alias));
		assert!(!AccountToAlias::<Test>::contains_key(&who_account));
		assert!(!IdentityOf::<Test>::contains_key(&who_account));
		assert!(!UsernameOf::<Test>::contains_key(&who_account));
		assert!(!UsernameInfoOf::<Test>::contains_key(&username));
	});
}

#[test]
fn clear_personal_identity_fails_if_username_was_reported() {
	new_test_ext().execute_with(|| {
		// Person A with a username exists
		let (who_account, alias, username) = prepare_personal_identity();

		// Person B needs some funds to be able to report
		assert_ok!(Balances::mint_into(&account(12), 10));
		// Person A needs some funds to be able to clear their identity
		assert_ok!(Balances::mint_into(&who_account, 10000));

		// Just to move in time a little
		run_to_block(12);

		// Person B reports the username of person A
		assert_ok!(Identity::report_username(RuntimeOrigin::signed(account(12)), username.clone()));

		// After seeing that a judgement is ongoing on their username,
		// the person A tries to clear their identity but the attempt fails
		assert_noop!(
			Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())),
			Error::<Test>::UsernameJudgementOngoing
		);

		// Once the case on the username is closed
		PendingUsernameReports::<Test>::take(alias);

		// The identity can be cleared
		assert_ok!(Identity::clear_personal_identity(RuntimeOrigin::signed(who_account.clone())));
	});
}

#[test]
fn regular_username_calls_fail_for_people() {
	new_test_ext().execute_with(|| {
		// set up authority
		let initial_authority_balance = 1000;
		let authority = account(100);
		Balances::make_free_balance_be(&authority, initial_authority_balance);
		let suffix: Vec<u8> = b"test".to_vec();
		let allocation: u32 = 10;
		assert_ok!(Identity::add_username_authority(
			RuntimeOrigin::root(),
			authority.clone(),
			suffix.clone(),
			allocation
		));

		// set up username
		let username: Username<Test> = b"42".to_vec().try_into().unwrap();

		// set up user and sign message
		let public = sr25519_generate(0.into(), None);
		let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
		let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];
		let signature =
			MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &alias[..]).unwrap());

		assert_ok!(Identity::set_personal_identity(
			RuntimeOrigin::signed(who_account.clone()),
			who_account.clone(),
			signature.clone(),
			username.clone(),
		));

		assert_noop!(
			Identity::set_primary_username(
				RuntimeOrigin::signed(who_account.clone()),
				username.clone()
			),
			Error::<Test>::InvalidTarget
		);

		// set up another username
		let second_username = test_username_of(b"101".to_vec(), suffix.clone());
		let now = frame_system::Pallet::<Test>::block_number();
		let expiration = now + <<Test as Config>::PendingUsernameExpiration as Get<u64>>::get();

		assert_ok!(Identity::set_username_for(
			RuntimeOrigin::signed(authority.clone()),
			who_account.clone(),
			second_username.clone().into(),
			None,
			true,
		));

		// Should be pending
		assert_eq!(
			PendingUsernames::<Test>::get::<&Username<Test>>(&second_username),
			Some((who_account.clone(), expiration, Provider::Allocation))
		);

		// The user is a person, so they can't accept authority usernames.
		assert_noop!(
			Identity::accept_username(RuntimeOrigin::signed(who_account), second_username),
			Error::<Test>::InvalidTarget
		);
	});
}

mod username_reporting {
	use super::*;
	use crate::types::UsernameReport;
	use frame_support::traits::fungible::Mutate;

	#[test]
	fn fails_given_unrecognised_person() {
		new_test_ext().execute_with(|| {
			let username: Username<Test> = b"42".to_vec().try_into().unwrap();

			// given the EnsurePerson setting in these tests, all signed origins are recognised as
			// persons

			assert_noop!(
				Identity::report_username(RuntimeOrigin::none(), username.clone()),
				BadOrigin
			);
			assert_noop!(Identity::report_username(RuntimeOrigin::root(), username), BadOrigin);
		});
	}

	#[test]
	fn reported_username_not_exists() {
		new_test_ext().execute_with(|| {
			let username: Username<Test> = b"42".to_vec().try_into().unwrap();
			assert_noop!(
				Identity::report_username(RuntimeOrigin::signed(account(0)), username),
				Error::<Test>::NoUsername
			);
		});
	}

	#[test]
	fn username_already_reported() {
		new_test_ext().execute_with(|| {
			let username: Username<Test> = b"42".to_vec().try_into().unwrap();

			// User set-up
			let public = sr25519_generate(0.into(), None);
			let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
			let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];
			let signature =
				MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &alias[..]).unwrap());

			assert_ok!(Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account.clone(),
				signature.clone(),
				username.clone(),
			));

			// Overwriting pending username reports of the user for that username,
			// to simulate a report already done
			let case_id: Alias = [14; 32];
			let username_report: UsernameReport<
				sp_core::crypto::AccountId32,
				PersonalData,
				OracleTicketOf<Test>,
			> = types::UsernameReport { reporter: account(12), username: username.clone(), case_id };
			PendingUsernameReports::<Test>::insert(alias, username_report);

			assert_noop!(
				Identity::report_username(RuntimeOrigin::signed(account(0)), username),
				Error::<Test>::AlreadyReported
			);
		});
	}

	#[test]
	fn username_recently_reported() {
		new_test_ext().execute_with(|| {
			let username: Username<Test> = b"42".to_vec().try_into().unwrap();

			// User set-up
			let public = sr25519_generate(0.into(), None);
			let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
			let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];
			let signature =
				MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &alias[..]).unwrap());

			assert_ok!(Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account.clone(),
				signature.clone(),
				username.clone(),
			));

			// Just to move a little in time
			run_to_block(17);

			// Simulating username being reported 2 blocks ago
			let mut pid = PersonIdentities::<Test>::get(alias).unwrap();
			pid.username_last_reported_at = Some(15);
			PersonIdentities::<Test>::insert(alias, pid);

			assert_noop!(
				Identity::report_username(RuntimeOrigin::signed(account(0)), username),
				Error::<Test>::LastUsernameReportTooRecent
			);
		});
	}

	/// Shows the flow of username reporting.
	/// Call to report_username should result with:
	/// - request to oracle for judgement on the provided username,
	/// - information related to the judgement request stored in pallet storage item,
	/// - block at which the report was made stored in personal identity metadata.
	#[test]
	pub fn username_reporting_flow() {
		new_test_ext().execute_with(|| {
			// Person A - set-up of personal identity with a username
			let username: Username<Test> = b"42".to_vec().try_into().unwrap();

			let public = sr25519_generate(0.into(), None);
			let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
			let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];
			let signature =
				MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &alias[..]).unwrap());

			assert_ok!(Identity::set_personal_identity(
				RuntimeOrigin::signed(who_account.clone()),
				who_account.clone(),
				signature.clone(),
				username.clone(),
			));

			// Person B needs some funds to be able to report
			assert_ok!(Balances::mint_into(&account(12), 10));

			// No reserved balance at this point
			assert_eq!(Balances::reserved_balance(account(12)), 0);

			// Just to move in time a little
			run_to_block(12);

			// Person B reports the username of person A
			assert_ok!(Identity::report_username(
				RuntimeOrigin::signed(account(12)),
				username.clone()
			));

			// A balance reserve is executed on Person's B account
			assert_eq!(Balances::reserved_balance(account(12)), 5);

			// Information about the username report is stored
			let report = PendingUsernameReports::<Test>::get(alias);
			assert!(report.is_some());
			let report = report.unwrap();
			assert_eq!(report.case_id, alias);
			assert_eq!(report.username, username);

			// Date of the last report stored in personal identity metadata
			let pid = PersonIdentities::<Test>::get(alias).unwrap();
			assert_eq!(pid.username_last_reported_at, Some(12));

			// A judgement by the oracle is requested
			if let Some(Statement::UsernameValid { username: reported_username }) =
				simple_oracle::StatementsToJudge::<Test>::get(report.case_id)
			{
				assert_eq!(reported_username, username);
			} else {
				panic!("statement is not UsernameValid");
			}
		});
	}
}

mod username_report_judgement {
	use super::*;
	use crate::types::UsernameReport;
	use frame_support::traits::fungible::Mutate;

	#[test]
	fn fails_given_unknown_alias() {
		new_test_ext().execute_with(|| {
			let ticket: OracleTicketOf<Test> = [1; 32];
			let context: JudgementContext = [0u8; 64].to_vec().try_into().unwrap();
			let judgement = OracleJudgement::Truth(Truth::True);

			assert_noop!(
				Identity::reported_username_judged(
					RuntimeOrigin::root(),
					ticket,
					context,
					judgement
				),
				Error::<Test>::NoIdentity
			);
		});
	}

	#[test]
	fn fails_given_unexpected_alias() {
		new_test_ext().execute_with(|| {
			let (_, alias, _) = prepare_personal_identity();

			let ticket: OracleTicketOf<Test> = [1; 32];
			let mut context: JudgementContext = [0u8; 64].to_vec().try_into().unwrap();
			context[..32].copy_from_slice(&alias[..]);
			let judgement = OracleJudgement::Truth(Truth::True);

			assert_noop!(
				Identity::reported_username_judged(
					RuntimeOrigin::root(),
					ticket,
					context,
					judgement
				),
				Error::<Test>::UnexpectedJudgement
			);
		});
	}

	#[test]
	fn fails_given_unexpected_case_id() {
		new_test_ext().execute_with(|| {
			let (_, alias, username) = prepare_personal_identity();

			let ticket: OracleTicketOf<Test> = [1; 32];

			// The case had previously been created
			let case_id: Alias = [14; 32];
			let username_report: UsernameReport<
				sp_core::crypto::AccountId32,
				PersonalData,
				OracleTicketOf<Test>,
			> = types::UsernameReport { reporter: account(12), username: username.clone(), case_id };
			PendingUsernameReports::<Test>::insert(alias, username_report);

			let mut context: JudgementContext = [0u8; 64].to_vec().try_into().unwrap();
			context[..32].copy_from_slice(&alias[..]);

			let judgement = OracleJudgement::Truth(Truth::True);

			assert_noop!(
				Identity::reported_username_judged(
					RuntimeOrigin::root(),
					ticket,
					context,
					judgement
				),
				Error::<Test>::UnexpectedJudgement
			);
		});
	}

	#[test]
	fn username_judged_as_valid_results_with_reporters_deposit_slash() {
		new_test_ext().execute_with(|| {
			let (_, alias, username) = prepare_personal_identity();

			// Person B needs some funds to be able to report
			assert_ok!(Balances::mint_into(&account(12), 10));

			// No reserved balance at this point
			assert_eq!(Balances::reserved_balance(account(12)), 0);

			// Just to move in time a little
			run_to_block(12);

			// Person B reports the username of person A
			assert_ok!(Identity::report_username(
				RuntimeOrigin::signed(account(12)),
				username.clone()
			));

			// A balance reserve is executed on Person's B account
			assert_eq!(Balances::reserved_balance(account(12)), 5);

			// Username report stored
			let report = PendingUsernameReports::<Test>::get(alias).unwrap();

			// Oracle returns with a judgement on the username
			let ticket: OracleTicketOf<Test> = report.case_id;
			let mut context: JudgementContext = [0u8; 64].to_vec().try_into().unwrap();
			context[..32].copy_from_slice(&alias[..]);
			let judgement = OracleJudgement::Truth(Truth::True);

			assert_ok!(Identity::reported_username_judged(
				RuntimeOrigin::root(),
				ticket,
				context,
				judgement
			));

			// No balance reserved on Person's B account anymore
			assert_eq!(Balances::reserved_balance(account(12)), 0);

			// But the funds were not returned to his account, thus they were slashed
			assert_eq!(Balances::free_balance(account(12)), 5);
		});
	}

	#[test]
	fn username_judged_as_invalid_results_with_deposit_release_and_user_ban() {
		new_test_ext().execute_with(|| {
			let (_, alias, username) = prepare_personal_identity();

			// Person B needs some funds to be able to report
			assert_ok!(Balances::mint_into(&account(12), 10));

			// No reserved balance at this point
			assert_eq!(Balances::reserved_balance(account(12)), 0);

			// Just to move in time a little
			run_to_block(12);

			// Person B reports the username of person A
			assert_ok!(Identity::report_username(
				RuntimeOrigin::signed(account(12)),
				username.clone()
			));

			// A balance reserve is executed on Person's B account
			assert_eq!(Balances::reserved_balance(account(12)), 5);

			// Username report stored in metadata
			let report = PendingUsernameReports::<Test>::get(alias).unwrap();

			// Oracle returns with a judgement on the username
			let ticket: OracleTicketOf<Test> = report.case_id;
			let mut context: JudgementContext = [0u8; 64].to_vec().try_into().unwrap();
			context[..32].copy_from_slice(&alias[..]);
			let judgement = OracleJudgement::Truth(Truth::False);

			assert_ok!(Identity::reported_username_judged(
				RuntimeOrigin::root(),
				ticket,
				context,
				judgement
			));

			// No balance reserved on Person's B account anymore
			assert_eq!(Balances::reserved_balance(account(12)), 0);
			// And the funds were returned to his account
			assert_eq!(Balances::free_balance(account(12)), 10);

			// The Identity behind the reported username is banned now
			assert!(PersonIdentities::<Test>::get(alias).unwrap().banned)
		});
	}
}

pub fn prepare_personal_identity() -> (AccountIdOf<Test>, Alias, Username<Test>) {
	let username: Username<Test> = b"42".to_vec().try_into().unwrap();

	let public = sr25519_generate(0.into(), None);
	let who_account: AccountIdOf<Test> = MultiSigner::Sr25519(public).into_account();
	let alias: Alias = [<AccountIdOf<Test> as AsRef<[u8]>>::as_ref(&who_account)[0]; 32];
	let signature = MultiSignature::Sr25519(sr25519_sign(0.into(), &public, &alias[..]).unwrap());

	assert_ok!(Identity::set_personal_identity(
		RuntimeOrigin::signed(who_account.clone()),
		who_account.clone(),
		signature.clone(),
		username.clone(),
	));

	(who_account, alias, username)
}
