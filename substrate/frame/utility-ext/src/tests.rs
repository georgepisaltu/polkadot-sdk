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

// Tests for the Utility Extension Pallet

#![cfg(test)]

use super::*;

use crate as pallet_utility_ext;
use frame_support::{
	derive_impl, parameter_types,
	traits::{ConstU32, ConstU8, Everything},
	weights::{IdentityFee, Weight},
};
use frame_system::EnsureRoot;
use pallet_collective::{EnsureProportionAtLeast, Instance1};
use pallet_transaction_payment::{ChargeTransactionPayment, FungibleAdapter};
use sp_runtime::BuildStorage;

type BlockNumber = u64;

// example module to test behaviors.
#[frame_support::pallet(dev_mode)]
pub mod example {
	use frame_support::{dispatch::WithPostDispatchInfo, pallet_prelude::*};
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type CouncilOrigin: EnsureOrigin<Self::RuntimeOrigin>;
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(*_weight)]
		pub fn noop(_origin: OriginFor<T>, _weight: Weight) -> DispatchResult {
			Ok(())
		}

		/// Authorized while nothing was claimed yet. Like some in-tree calls, dispatch relies on
		/// `authorize` having just run and does not check again.
		#[pallet::call_index(4)]
		#[pallet::weight(Weight::zero())]
		#[pallet::weight_of_authorize(Weight::zero())]
		#[pallet::authorize(Self::authorize_claim)]
		pub fn claim(origin: OriginFor<T>) -> DispatchResult {
			ensure_authorized(origin)?;
			Claimed::<T>::put(true);
			Claims::<T>::mutate(|n| *n += 1);
			Ok(())
		}

		#[pallet::call_index(3)]
		#[pallet::weight((Weight::from_parts(10, 0), Pays::No))]
		pub fn free(origin: OriginFor<T>, err: bool) -> DispatchResult {
			ensure_signed(origin)?;
			ensure!(!err, Error::<T>::Custom);
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(*_start_weight)]
		pub fn foobar(
			origin: OriginFor<T>,
			err: bool,
			_start_weight: Weight,
			end_weight: Option<Weight>,
		) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;
			Calls::<T>::mutate(|n| *n += 1);
			if err {
				let error: DispatchError = Error::<T>::Custom.into();
				if let Some(weight) = end_weight {
					Err(error.with_weight(weight))
				} else {
					Err(error)?
				}
			} else {
				Ok(end_weight.into())
			}
		}

		#[pallet::call_index(2)]
		#[pallet::weight(0)]
		pub fn council_only(origin: OriginFor<T>) -> DispatchResult {
			T::CouncilOrigin::ensure_origin(origin)?;
			CouncilCalls::<T>::mutate(|n| *n += 1);
			Ok(())
		}

		#[pallet::call_index(5)]
		#[pallet::weight((Weight::from_parts(10, 0), DispatchClass::Operational))]
		pub fn operational(origin: OriginFor<T>) -> DispatchResult {
			ensure_signed(origin)?;
			Ok(())
		}
	}

	#[pallet::error]
	pub enum Error<T> {
		Custom,
	}

	/// How many times `foobar` was dispatched, including failed dispatches.
	#[pallet::storage]
	pub type Calls<T: Config> = StorageValue<_, u32, ValueQuery>;

	/// How many times `council_only` was dispatched.
	#[pallet::storage]
	pub type CouncilCalls<T: Config> = StorageValue<_, u32, ValueQuery>;

	#[pallet::storage]
	pub type Claimed<T: Config> = StorageValue<_, bool, ValueQuery>;

	/// How many times `claim` was dispatched.
	#[pallet::storage]
	pub type Claims<T: Config> = StorageValue<_, u32, ValueQuery>;

	impl<T: Config> Pallet<T> {
		pub fn authorize_claim(_source: TransactionSource) -> TransactionValidityWithRefund {
			if Claimed::<T>::get() {
				return Err(InvalidTransaction::Stale.into());
			}
			let validity =
				ValidTransaction { provides: vec![b"claim".to_vec()], ..Default::default() };
			Ok((validity, Weight::zero()))
		}
	}
}

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		Balances: pallet_balances,
		TransactionPayment: pallet_transaction_payment,
		Council: pallet_collective::<Instance1>,
		Utility: pallet_utility,
		UtilityExt: pallet_utility_ext,
		Example: example,
	}
);

parameter_types! {
	pub BlockWeights: frame_system::limits::BlockWeights =
		frame_system::limits::BlockWeights::simple_max(Weight::MAX);
}
#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type BaseCallFilter = Everything;
	type BlockWeights = BlockWeights;
	type Block = Block;
	type AccountData = pallet_balances::AccountData<u64>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type AccountStore = System;
}

/// Fees are the transaction's length plus its weight's `ref_time`, unless [`make_fees_free`]
/// was called.
#[derive_impl(pallet_transaction_payment::config_preludes::TestDefaultConfig)]
impl pallet_transaction_payment::Config for Test {
	type OnChargeTransaction = FungibleAdapter<Balances, ()>;
	type OperationalFeeMultiplier = ConstU8<5>;
	type WeightToFee = MockFee;
	type LengthToFee = MockFee;
}

pub const FREE_FEES: &[u8] = b"FreeFees";

/// Make every fee zero for the rest of the test.
pub fn make_fees_free() {
	sp_io::storage::set(FREE_FEES, &[]);
}

pub struct MockFee;
impl frame_support::weights::WeightToFee for MockFee {
	type Balance = u64;
	fn weight_to_fee(weight: &Weight) -> u64 {
		if sp_io::storage::exists(FREE_FEES) {
			0
		} else {
			IdentityFee::<u64>::weight_to_fee(weight)
		}
	}
}

parameter_types! {
	pub const MotionDuration: BlockNumber = 3;
	pub const MaxProposals: u32 = 100;
	pub const MaxMembers: u32 = 100;
	pub MaxProposalWeight: Weight = sp_runtime::Perbill::from_percent(50) * BlockWeights::get().max_block;
}

type CouncilCollective = pallet_collective::Instance1;
impl pallet_collective::Config<CouncilCollective> for Test {
	type RuntimeOrigin = RuntimeOrigin;
	type Proposal = RuntimeCall;
	type RuntimeEvent = RuntimeEvent;
	type MotionDuration = MotionDuration;
	type MaxProposals = MaxProposals;
	type MaxMembers = MaxMembers;
	type DefaultVote = pallet_collective::PrimeDefaultVote;
	type WeightInfo = ();
	type SetMembersOrigin = EnsureRoot<Self::AccountId>;
	type MaxProposalWeight = MaxProposalWeight;
	type DisapproveOrigin = EnsureRoot<Self::AccountId>;
	type KillOrigin = EnsureRoot<Self::AccountId>;
	type Consideration = ();
}

impl example::Config for Test {
	type CouncilOrigin = EnsureProportionAtLeast<u64, Instance1, 3, 4>;
}

impl pallet_utility::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type PalletsOrigin = OriginCaller;
	type WeightInfo = ();
}

impl Config for Test {
	type InnerExtension = InnerExtension;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = BenchmarkItems;
	type MaxMultiOriginBatch = ConstU32<4>;
	type MultiOriginCallFilter = MultiOriginCallFilter;
	type WeightInfo = ();
}

/// Keeps `Example::noop` out of multi-origin batches.
pub struct MultiOriginCallFilter;
impl Contains<RuntimeCall> for MultiOriginCallFilter {
	fn contains(c: &RuntimeCall) -> bool {
		!matches!(c, RuntimeCall::Example(ExampleCall::noop { .. }))
	}
}

/// The inner extension pipeline of multi-origin batch items in tests.
pub type InnerExtension = (
	ExpectImplication,
	SetOrigin,
	frame_system::AuthorizeCall<Test>,
	frame_system::CheckNonce<Test>,
	ChargeTransactionPayment<Test>,
);

/// Builds the benchmark items: signed by account 1.
#[cfg(feature = "runtime-benchmarks")]
pub struct BenchmarkItems;
#[cfg(feature = "runtime-benchmarks")]
impl BenchmarkHelper<Test> for BenchmarkItems {
	fn setup() -> OriginCaller {
		OriginCaller::system(frame_system::RawOrigin::Signed(1))
	}

	fn item(call: RuntimeCall, nonce: u32, implication: Vec<u8>) -> MultiOriginItemOf<Test> {
		MultiOriginItem::new(
			call,
			(
				ExpectImplication(implication),
				SetOrigin::signed(1),
				frame_system::AuthorizeCall::new(),
				frame_system::CheckNonce::from(nonce),
				ChargeTransactionPayment::from(0),
			),
			Self::setup(),
		)
	}
}

use multi_origin_mock::*;

/// Mock pieces for the multi-origin batch tests.
mod multi_origin_mock {
	use super::*;
	use frame_support::{pallet_prelude::TransactionSource, storage};
	use sp_runtime::{
		traits::{Implication, TransactionExtension, ValidateResult},
		transaction_validity::{InvalidTransaction, TransactionValidityError, ValidTransaction},
		DispatchResult,
	};

	/// The runtime's transaction extension pipeline in tests.
	pub type TxExtension = (
		frame_system::CheckNonce<Test>,
		frame_system::CheckWeight<Test>,
		MultiOriginBatch<Test>,
		ChargeTransactionPayment<Test>,
	);
	pub type UncheckedExtrinsic = sp_runtime::generic::UncheckedExtrinsic<
		u64,
		RuntimeCall,
		sp_runtime::testing::TestSignature,
		TxExtension,
	>;

	/// Keys of the counters `SetOrigin` keeps in storage.
	pub const SET_ORIGIN_PREPARED: &[u8] = b"SetOrigin::prepared";
	pub const SET_ORIGIN_POST_DISPATCHED: &[u8] = b"SetOrigin::post_dispatched";
	/// Set to make `SetOrigin::post_dispatch` fail.
	pub const SET_ORIGIN_FAIL_POST_DISPATCH: &[u8] = b"SetOrigin::fail_post_dispatch";
	pub const SET_ORIGIN_POST_DISPATCH_ERROR: InvalidTransaction = InvalidTransaction::Custom(7);
	/// The weight `SetOrigin` declares.
	pub const SET_ORIGIN_WEIGHT: Weight = Weight::from_parts(7, 0);

	/// A test inner extension which stands in for a signature check: it fails with `BadProof`
	/// unless the base implication it is validated with is the one it carries.
	#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, TypeInfo, Debug)]
	pub struct ExpectImplication(pub Vec<u8>);

	impl TransactionExtension<RuntimeCall> for ExpectImplication {
		const IDENTIFIER: &'static str = "ExpectImplication";
		type Implicit = ();
		type Val = ();
		type Pre = ();

		fn weight(&self, _: &RuntimeCall) -> Weight {
			Weight::zero()
		}

		fn validate(
			&self,
			origin: RuntimeOrigin,
			_: &RuntimeCall,
			_: &DispatchInfo,
			_: usize,
			_: (),
			inherited_implication: &impl Implication,
			_: TransactionSource,
		) -> ValidateResult<(), RuntimeCall> {
			if inherited_implication.parts().base.encode() != self.0 {
				return Err(InvalidTransaction::BadProof.into());
			}
			Ok((ValidTransaction::default(), (), origin))
		}

		sp_runtime::impl_tx_ext_default!(RuntimeCall; prepare);
	}

	/// A test inner extension which authorizes the origin it carries and counts how often its
	/// `prepare` and `post_dispatch` run.
	#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, TypeInfo, Debug)]
	pub struct SetOrigin(pub OriginCaller);

	impl SetOrigin {
		pub fn signed(who: u64) -> Self {
			Self(OriginCaller::system(frame_system::RawOrigin::Signed(who)))
		}
		pub fn none() -> Self {
			Self(OriginCaller::system(frame_system::RawOrigin::None))
		}
		pub fn council() -> Self {
			Self(OriginCaller::Council(pallet_collective::RawOrigin::Members(3, 3)))
		}
		pub fn prepared() -> u32 {
			storage::unhashed::get_or_default(SET_ORIGIN_PREPARED)
		}
		pub fn post_dispatched() -> u32 {
			storage::unhashed::get_or_default(SET_ORIGIN_POST_DISPATCHED)
		}
		pub fn fail_post_dispatch() {
			storage::unhashed::put(SET_ORIGIN_FAIL_POST_DISPATCH, &true);
		}
		fn bump(key: &[u8]) {
			storage::unhashed::put(key, &(storage::unhashed::get_or_default::<u32>(key) + 1));
		}
	}

	impl TransactionExtension<RuntimeCall> for SetOrigin {
		const IDENTIFIER: &'static str = "SetOrigin";
		type Implicit = ();
		type Val = ();
		type Pre = ();

		fn weight(&self, _: &RuntimeCall) -> Weight {
			SET_ORIGIN_WEIGHT
		}

		fn validate(
			&self,
			mut origin: RuntimeOrigin,
			_: &RuntimeCall,
			_: &DispatchInfo,
			_: usize,
			_: (),
			_: &impl Implication,
			_: TransactionSource,
		) -> ValidateResult<(), RuntimeCall> {
			origin.set_caller(self.0.clone());
			Ok((ValidTransaction::default(), (), origin))
		}

		fn prepare(
			self,
			_: (),
			_: &RuntimeOrigin,
			_: &RuntimeCall,
			_: &DispatchInfo,
			_: usize,
		) -> Result<(), TransactionValidityError> {
			Self::bump(SET_ORIGIN_PREPARED);
			Ok(())
		}

		fn post_dispatch_details(
			_: (),
			_: &DispatchInfo,
			_: &PostDispatchInfo,
			_: usize,
			_: &DispatchResult,
		) -> Result<Weight, TransactionValidityError> {
			Self::bump(SET_ORIGIN_POST_DISPATCHED);
			if storage::unhashed::get_or_default::<bool>(SET_ORIGIN_FAIL_POST_DISPATCH) {
				return Err(SET_ORIGIN_POST_DISPATCH_ERROR.into());
			}
			Ok(Weight::zero())
		}
	}
}

type ExampleCall = example::Call<Test>;

pub const INITIAL_BALANCE: u64 = 1_000_000_000_000;

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: (1..=5).map(|who| (who, INITIAL_BALANCE)).collect(),
		..Default::default()
	}
	.assimilate_storage(&mut t)
	.unwrap();

	pallet_collective::GenesisConfig::<Test, Instance1> {
		members: vec![1, 2, 3],
		phantom: Default::default(),
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}

mod multi_origin {
	use super::*;
	use frame_support::{
		assert_noop, assert_ok,
		dispatch::{GetDispatchInfo, Pays},
		pallet_prelude::TransactionSource,
	};
	use frame_system::Call as SystemCall;
	use sp_runtime::{
		generic::SignedPayload,
		testing::TestSignature,
		traits::{Applyable, BadOrigin, Checkable, Dispatchable, IdentityLookup},
		transaction_validity::{InvalidTransaction, TransactionValidityError, ValidTransaction},
		ApplyExtrinsicResultWithInfo, DispatchError,
	};

	type BalancesCall = pallet_balances::Call<Test>;
	type UtilityCall = pallet_utility::Call<Test>;
	type UtilityExtCall = crate::Call<Test>;

	/// The spec of an item: what it dispatches, who authorizes it and what it declares.
	#[derive(Clone)]
	struct ItemSpec {
		call: RuntimeCall,
		set_origin: SetOrigin,
		/// The origin the item states; by default the one `set_origin` authorizes.
		expected: OriginCaller,
		nonce: u32,
		tip: u64,
	}

	/// An item dispatching `call` with the origin `set_origin` authorizes, with the current
	/// nonce of that origin if it is signed.
	fn spec(call: RuntimeCall, set_origin: SetOrigin) -> ItemSpec {
		let nonce = match &set_origin.0 {
			OriginCaller::system(frame_system::RawOrigin::Signed(who)) => {
				System::account_nonce(who)
			},
			_ => 0,
		};
		ItemSpec { call, expected: set_origin.0.clone(), set_origin, nonce, tip: 0 }
	}

	fn with_nonce(mut spec: ItemSpec, nonce: u32) -> ItemSpec {
		spec.nonce = nonce;
		spec
	}

	fn with_tip(mut spec: ItemSpec, tip: u64) -> ItemSpec {
		spec.tip = tip;
		spec
	}

	fn expecting(mut spec: ItemSpec, origin: OriginCaller) -> ItemSpec {
		spec.expected = origin;
		spec
	}

	fn signed_by(who: u64) -> OriginCaller {
		OriginCaller::system(frame_system::RawOrigin::Signed(who))
	}

	/// An item authorized by `AuthorizeCall`: nothing sets an origin before it.
	fn authorized(call: RuntimeCall) -> ItemSpec {
		expecting(
			spec(call, SetOrigin::none()),
			OriginCaller::system(frame_system::RawOrigin::Authorized),
		)
	}

	fn call_transfer(dest: u64, value: u64) -> RuntimeCall {
		RuntimeCall::Balances(BalancesCall::transfer_allow_death { dest, value })
	}

	fn call_foobar(err: bool, start: u64, end: Option<u64>) -> RuntimeCall {
		RuntimeCall::Example(ExampleCall::foobar {
			err,
			start_weight: Weight::from_parts(start, 0),
			end_weight: end.map(|w| Weight::from_parts(w, 0)),
		})
	}

	fn call_remark() -> RuntimeCall {
		RuntimeCall::System(SystemCall::remark { remark: vec![] })
	}

	/// The items of a batch in `mode` submitted by `submitter` with `nonce`, each "signed" over
	/// the implication of its batch.
	fn build_items(
		submitter: u64,
		nonce: u32,
		mode: BatchMode,
		specs: &[ItemSpec],
	) -> Vec<MultiOriginItemOf<Test>> {
		let items_hash =
			Pallet::<Test>::items_hash(specs.iter().map(|spec| (&spec.call, &spec.expected)));
		specs
			.iter()
			.enumerate()
			.map(|(index, spec)| {
				let implication = ItemImplication {
					mode,
					submitter: &submitter,
					nonce,
					index: index as u32,
					items_hash: &items_hash,
				}
				.encode();
				MultiOriginItem::new(
					spec.call.clone(),
					(
						ExpectImplication(implication),
						spec.set_origin.clone(),
						frame_system::AuthorizeCall::new(),
						frame_system::CheckNonce::from(spec.nonce),
						ChargeTransactionPayment::from(spec.tip),
					),
					spec.expected.clone(),
				)
			})
			.collect()
	}

	fn batch_call(mode: BatchMode, items: Vec<MultiOriginItemOf<Test>>) -> RuntimeCall {
		let items = items.try_into().expect("at most `MaxMultiOriginBatch` items");
		match mode {
			BatchMode::Stop => {
				RuntimeCall::UtilityExt(UtilityExtCall::batch_multi_origin { items })
			},
			BatchMode::Continue => {
				RuntimeCall::UtilityExt(UtilityExtCall::force_batch_multi_origin { items })
			},
		}
	}

	fn tx_ext(nonce: u32) -> TxExtension {
		(
			frame_system::CheckNonce::from(nonce),
			frame_system::CheckWeight::new(),
			MultiOriginBatch::new(),
			ChargeTransactionPayment::from(0),
		)
	}

	/// A transaction of `call` signed by `who` with their current nonce.
	fn signed_tx(who: u64, call: RuntimeCall) -> UncheckedExtrinsic {
		let ext = tx_ext(System::account_nonce(who));
		let payload = SignedPayload::new(call.clone(), ext.clone())
			.expect("implicit data is available")
			.using_encoded(|payload| payload.to_vec());
		UncheckedExtrinsic::new_signed(call, who, TestSignature(who, payload), ext)
	}

	/// A batch of `specs` in `mode`, submitted by `submitter` with their current nonce.
	fn batch_tx(submitter: u64, mode: BatchMode, specs: &[ItemSpec]) -> UncheckedExtrinsic {
		let nonce = System::account_nonce(submitter);
		signed_tx(submitter, batch_call(mode, build_items(submitter, nonce, mode, specs)))
	}

	fn check(
		uxt: UncheckedExtrinsic,
	) -> (<UncheckedExtrinsic as Checkable<IdentityLookup<u64>>>::Checked, DispatchInfo, usize) {
		let info = uxt.get_dispatch_info();
		let len = uxt.encoded_size();
		let xt =
			<UncheckedExtrinsic as Checkable<IdentityLookup<u64>>>::check(uxt, &Default::default())
				.expect("test signatures check");
		(xt, info, len)
	}

	fn validate(uxt: UncheckedExtrinsic) -> Result<ValidTransaction, TransactionValidityError> {
		let (xt, info, len) = check(uxt);
		xt.validate::<Test>(TransactionSource::External, &info, len)
	}

	fn apply(uxt: UncheckedExtrinsic) -> ApplyExtrinsicResultWithInfo<PostDispatchInfo> {
		let (xt, info, len) = check(uxt);
		xt.apply::<Test>(&info, len)
	}

	/// Apply a batch and assert the transaction itself went through.
	fn apply_ok(uxt: UncheckedExtrinsic) -> PostDispatchInfo {
		apply(uxt).expect("the transaction is valid").expect("the batch call succeeds")
	}

	/// The fee for `weight` and `len`, the only two things fees depend on in this mock.
	fn fee(weight: Weight, len: usize) -> u64 {
		weight.ref_time() + len as u64
	}

	/// What the submitter of `uxt` pays: the batch overhead, the item pipelines, the outer
	/// pipeline and the transaction's length.
	fn submitter_fee(uxt: &UncheckedExtrinsic) -> u64 {
		let info = uxt.get_dispatch_info();
		let (items, mode) = Pallet::<Test>::batch_items(&uxt.function).expect("a batch");
		let share =
			Pallet::<Test>::submitter_weight(items, mode).saturating_add(info.extension_weight);
		fee(share, uxt.encoded_size())
	}

	/// What the origin of an item dispatching `call` pays: the call's weight.
	fn item_fee(call: &RuntimeCall) -> u64 {
		fee(call.get_dispatch_info().call_weight, 0)
	}

	fn balance(who: u64) -> u64 {
		Balances::free_balance(who)
	}

	fn pallet_events() -> Vec<Event> {
		System::events()
			.into_iter()
			.filter_map(|record| match record.event {
				RuntimeEvent::UtilityExt(event) => Some(event),
				_ => None,
			})
			.collect()
	}

	fn invalid(error: InvalidTransaction) -> ItemError {
		ItemError::Invalid(error.into())
	}

	/// Dispatch errors come back from events, which store them stripped of their messages.
	fn failed(error: impl Into<DispatchError>) -> ItemError {
		ItemError::Failed(error.into().stripped())
	}

	fn custom() -> ItemError {
		failed(example::Error::<Test>::Custom)
	}

	/// The weight of the item pipelines of the batch `uxt`.
	fn pipelines_weight(uxt: &UncheckedExtrinsic) -> Weight {
		let (items, _) = Pallet::<Test>::batch_items(&uxt.function).expect("a batch");
		Pallet::<Test>::items_extension_weight(items)
	}

	/// The outer pipeline's weight, which the pipeline adds to the batch's actual weight, minus
	/// what the fee payment extension refunds since it is skipped for batches.
	fn outer_weight(uxt: &UncheckedExtrinsic) -> Weight {
		uxt.get_dispatch_info()
			.extension_weight
			.saturating_sub(ChargeTransactionPayment::<Test>::from(0).weight(&uxt.function))
	}

	fn assert_fee_credit_empty() {
		assert_eq!(TransactionPayment::remaining_txfee::<u64>(), 0);
	}

	#[test]
	fn dispatches_each_item_with_its_own_origin() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_transfer(4, 100), SetOrigin::signed(1)),
				spec(call_transfer(4, 200), SetOrigin::signed(2)),
				spec(RuntimeCall::Example(ExampleCall::council_only {}), SetOrigin::council()),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let submitter_fee = submitter_fee(&uxt);
			assert!(submitter_fee > 0);

			apply_ok(uxt);

			assert_eq!(balance(4), INITIAL_BALANCE + 300);
			assert_eq!(balance(1), INITIAL_BALANCE - 100 - item_fee(&specs[0].call));
			assert_eq!(balance(2), INITIAL_BALANCE - 200 - item_fee(&specs[1].call));
			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			assert_eq!(example::CouncilCalls::<Test>::get(), 1);
			assert_eq!(System::account_nonce(1), 1);
			assert_eq!(System::account_nonce(2), 1);
			assert_eq!(System::account_nonce(3), 1);
			assert_eq!(SetOrigin::prepared(), 3);
			assert_eq!(SetOrigin::post_dispatched(), 3);
			assert_eq!(
				pallet_events(),
				vec![
					Event::ItemCompleted { index: 0 },
					Event::ItemCompleted { index: 1 },
					Event::ItemCompleted { index: 2 },
					Event::BatchCompleted,
				]
			);
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn items_of_one_signer_apply_in_sequence() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_transfer(4, 100), SetOrigin::signed(1)),
				with_nonce(spec(call_transfer(4, 100), SetOrigin::signed(1)), 1),
			];
			apply_ok(batch_tx(3, BatchMode::Stop, &specs));

			assert_eq!(balance(4), INITIAL_BALANCE + 200);
			assert_eq!(System::account_nonce(1), 2);
			assert_eq!(pallet_events().last(), Some(&Event::BatchCompleted));

			// Two items with the same nonce: the second is stale.
			let specs = [
				spec(call_transfer(4, 100), SetOrigin::signed(2)),
				spec(call_transfer(4, 100), SetOrigin::signed(2)),
			];
			apply_ok(batch_tx(3, BatchMode::Stop, &specs));
			assert_eq!(balance(4), INITIAL_BALANCE + 300);
			assert_eq!(System::account_nonce(2), 1);
			assert_eq!(
				pallet_events().last(),
				Some(&Event::BatchInterrupted {
					index: 1,
					error: invalid(InvalidTransaction::Stale)
				})
			);
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn submitter_can_also_sign_items() {
		new_test_ext().execute_with(|| {
			// The outer `CheckNonce` bumps the submitter's nonce before the items run.
			let specs = [
				with_nonce(spec(call_transfer(4, 100), SetOrigin::signed(1)), 1),
				spec(call_transfer(4, 100), SetOrigin::signed(2)),
				with_nonce(spec(call_transfer(4, 100), SetOrigin::signed(1)), 2),
			];
			let uxt = batch_tx(1, BatchMode::Stop, &specs);
			let submitter_fee = submitter_fee(&uxt);

			apply_ok(uxt);

			assert_eq!(balance(4), INITIAL_BALANCE + 300);
			assert_eq!(
				balance(1),
				INITIAL_BALANCE -
					200 - submitter_fee -
					item_fee(&specs[0].call) -
					item_fee(&specs[2].call)
			);
			assert_eq!(System::account_nonce(1), 3);
			assert_eq!(pallet_events().last(), Some(&Event::BatchCompleted));
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn submitter_pays_for_overhead_pipelines_and_length() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_foobar(false, 1_000, None), SetOrigin::signed(1)),
				spec(call_foobar(false, 2_000, Some(500)), SetOrigin::signed(2)),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let info = uxt.get_dispatch_info();
			let len = uxt.encoded_size();
			let submitter_fee = submitter_fee(&uxt);

			// The share is the batch overhead plus the item pipelines, plus the outer pipeline.
			let overhead = <Test as Config>::WeightInfo::batch_multi_origin(2);
			let pipelines = pipelines_weight(&uxt);
			assert!(pipelines.all_gte(SET_ORIGIN_WEIGHT.saturating_mul(2)));
			let share = overhead.saturating_add(pipelines).saturating_add(info.extension_weight);
			assert_eq!(submitter_fee, fee(share, len));
			// The share is not the batch's weight, which also has the calls.
			assert_eq!(
				info.call_weight,
				overhead.saturating_add(pipelines).saturating_add(Weight::from_parts(3_000, 0))
			);

			apply_ok(uxt);

			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			System::assert_has_event(
				pallet_transaction_payment::Event::<Test>::TransactionFeePaid {
					who: 3,
					actual_fee: submitter_fee,
					tip: 0,
				}
				.into(),
			);
			// Items pay for their calls only, refunds included.
			assert_eq!(balance(1), INITIAL_BALANCE - 1_000);
			assert_eq!(balance(2), INITIAL_BALANCE - 500);
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn items_pay_their_tips() {
		new_test_ext().execute_with(|| {
			let specs = [with_tip(spec(call_foobar(false, 1_000, None), SetOrigin::signed(1)), 50)];
			apply_ok(batch_tx(3, BatchMode::Stop, &specs));
			assert_eq!(balance(1), INITIAL_BALANCE - 1_000 - 50);
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn invalid_item_stops_the_batch_and_pays_nothing() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_transfer(4, 100), SetOrigin::signed(1)),
				// Future nonce.
				with_nonce(spec(call_transfer(4, 100), SetOrigin::signed(2)), 5),
				spec(call_transfer(4, 100), SetOrigin::signed(1)),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let submitter_fee = submitter_fee(&uxt);
			let pipelines = pipelines_weight(&uxt);
			let outer = outer_weight(&uxt);

			let post_info = apply_ok(uxt);

			// Only the first item applied.
			assert_eq!(balance(4), INITIAL_BALANCE + 100);
			assert_eq!(balance(1), INITIAL_BALANCE - 100 - item_fee(&specs[0].call));
			assert_eq!(System::account_nonce(1), 1);
			// The invalid item left no trace and paid nothing.
			assert_eq!(balance(2), INITIAL_BALANCE);
			assert_eq!(System::account_nonce(2), 0);
			assert_eq!(SetOrigin::prepared(), 1);
			assert_eq!(SetOrigin::post_dispatched(), 1);
			// The submitter pays the full share regardless.
			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			assert_eq!(
				pallet_events(),
				vec![
					Event::ItemCompleted { index: 0 },
					Event::BatchInterrupted {
						index: 1,
						error: invalid(InvalidTransaction::Future)
					},
				]
			);
			// The weight of the items which did not run is refunded, the invalid item's pipeline
			// is not.
			let overhead = <Test as Config>::WeightInfo::batch_multi_origin(2);
			assert_eq!(
				post_info.actual_weight,
				Some(
					overhead
						.saturating_add(pipelines.saturating_mul(2).saturating_div(3))
						.saturating_add(specs[0].call.get_dispatch_info().call_weight)
						.saturating_add(outer)
				)
			);
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn failed_item_stops_the_batch_and_pays() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_transfer(4, 100), SetOrigin::signed(1)),
				spec(call_foobar(true, 1_000, Some(300)), SetOrigin::signed(2)),
				spec(call_transfer(4, 100), SetOrigin::signed(1)),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let submitter_fee = submitter_fee(&uxt);
			let pipelines = pipelines_weight(&uxt);
			let outer = outer_weight(&uxt);

			let post_info = apply_ok(uxt);

			assert_eq!(balance(4), INITIAL_BALANCE + 100);
			assert_eq!(System::account_nonce(1), 1);
			// The failed item's pipeline applied: nonce bumped, fee paid for the actual weight.
			assert_eq!(balance(2), INITIAL_BALANCE - 300);
			assert_eq!(System::account_nonce(2), 1);
			assert_eq!(SetOrigin::prepared(), 2);
			assert_eq!(SetOrigin::post_dispatched(), 2);
			// The call's effects were reverted.
			assert_eq!(example::Calls::<Test>::get(), 0);
			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			assert_eq!(
				pallet_events(),
				vec![
					Event::ItemCompleted { index: 0 },
					Event::BatchInterrupted { index: 1, error: custom() },
				]
			);
			let overhead = <Test as Config>::WeightInfo::batch_multi_origin(2);
			assert_eq!(
				post_info.actual_weight,
				Some(
					overhead
						.saturating_add(pipelines.saturating_mul(2).saturating_div(3))
						.saturating_add(specs[0].call.get_dispatch_info().call_weight)
						.saturating_add(Weight::from_parts(300, 0))
						.saturating_add(outer)
				)
			);
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn force_batch_applies_every_item() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_transfer(4, 100), SetOrigin::signed(1)),
				with_nonce(spec(call_transfer(4, 100), SetOrigin::signed(2)), 5),
				spec(call_foobar(true, 1_000, None), SetOrigin::signed(2)),
				with_nonce(spec(call_transfer(4, 100), SetOrigin::signed(1)), 1),
			];
			let uxt = batch_tx(3, BatchMode::Continue, &specs);
			let submitter_fee = submitter_fee(&uxt);
			let pipelines = pipelines_weight(&uxt);
			let outer = outer_weight(&uxt);

			let post_info = apply_ok(uxt);

			assert_eq!(balance(4), INITIAL_BALANCE + 200);
			assert_eq!(System::account_nonce(1), 2);
			assert_eq!(balance(2), INITIAL_BALANCE - 1_000);
			assert_eq!(System::account_nonce(2), 1);
			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			assert_eq!(
				pallet_events(),
				vec![
					Event::ItemCompleted { index: 0 },
					Event::ItemFailed { index: 1, error: invalid(InvalidTransaction::Future) },
					Event::ItemFailed { index: 2, error: custom() },
					Event::ItemCompleted { index: 3 },
					Event::BatchCompletedWithErrors,
				]
			);
			let overhead = <Test as Config>::WeightInfo::force_batch_multi_origin(4);
			assert_eq!(
				post_info.actual_weight,
				Some(
					overhead
						.saturating_add(pipelines)
						.saturating_add(specs[0].call.get_dispatch_info().call_weight)
						.saturating_add(Weight::from_parts(1_000, 0))
						.saturating_add(specs[3].call.get_dispatch_info().call_weight)
						.saturating_add(outer)
				)
			);
			assert_fee_credit_empty();

			// Without failures it completes like the other variant.
			let specs = [spec(call_transfer(4, 100), SetOrigin::signed(1))];
			apply_ok(batch_tx(3, BatchMode::Continue, &specs));
			assert_eq!(pallet_events().last(), Some(&Event::BatchCompleted));
		});
	}

	#[test]
	fn weight_is_refunded() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_foobar(false, 1_000, Some(400)), SetOrigin::signed(1)),
				spec(call_foobar(false, 2_000, None), SetOrigin::signed(2)),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let info = uxt.get_dispatch_info();
			let pipelines = pipelines_weight(&uxt);
			let outer = outer_weight(&uxt);

			let post_info = apply_ok(uxt);

			let overhead = <Test as Config>::WeightInfo::batch_multi_origin(2);
			assert_eq!(
				info.call_weight,
				overhead.saturating_add(pipelines).saturating_add(Weight::from_parts(3_000, 0))
			);
			assert_eq!(
				post_info.actual_weight,
				Some(
					overhead
						.saturating_add(pipelines)
						.saturating_add(Weight::from_parts(2_400, 0))
						.saturating_add(outer)
				)
			);
		});
	}

	#[test]
	fn unauthorized_item_is_invalid() {
		new_test_ext().execute_with(|| {
			let specs = [spec(call_remark(), SetOrigin::none())];
			apply_ok(batch_tx(3, BatchMode::Stop, &specs));
			assert_eq!(
				pallet_events(),
				vec![Event::BatchInterrupted {
					index: 0,
					error: invalid(InvalidTransaction::UnknownOrigin)
				}]
			);
		});
	}

	#[test]
	fn item_origin_is_enforced() {
		new_test_ext().execute_with(|| {
			// Signed by 2, claims to be 1.
			let specs =
				[expecting(spec(call_transfer(4, 100), SetOrigin::signed(2)), signed_by(1))];
			apply_ok(batch_tx(3, BatchMode::Stop, &specs));
			assert_eq!(
				pallet_events(),
				vec![Event::BatchInterrupted {
					index: 0,
					error: invalid(InvalidTransaction::BadSigner)
				}]
			);
			assert_eq!(balance(2), INITIAL_BALANCE);
			assert_eq!(System::account_nonce(2), 0);
		});
	}

	#[test]
	fn item_is_bound_to_its_batch() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_transfer(2, 100), SetOrigin::signed(1)),
				spec(call_transfer(4, 100), SetOrigin::signed(2)),
			];
			let items = build_items(3, 0, BatchMode::Stop, &specs);

			// Alone.
			apply_ok(signed_tx(3, batch_call(BatchMode::Stop, vec![items[0].clone()])));
			// Next to a different item.
			let other = [specs[0].clone(), spec(call_transfer(5, 100), SetOrigin::signed(2))];
			let other_items = build_items(3, 1, BatchMode::Stop, &other);
			apply_ok(signed_tx(
				3,
				batch_call(BatchMode::Stop, vec![items[0].clone(), other_items[1].clone()]),
			));
			// At another position.
			apply_ok(signed_tx(
				3,
				batch_call(BatchMode::Stop, vec![items[1].clone(), items[0].clone()]),
			));
			assert_eq!(
				pallet_events(),
				vec![
					Event::BatchInterrupted {
						index: 0,
						error: invalid(InvalidTransaction::BadProof)
					},
					Event::BatchInterrupted {
						index: 0,
						error: invalid(InvalidTransaction::BadProof)
					},
					Event::BatchInterrupted {
						index: 0,
						error: invalid(InvalidTransaction::BadProof)
					},
				]
			);
			assert_eq!(balance(2), INITIAL_BALANCE);
			assert_eq!(System::account_nonce(1), 0);
			assert_eq!(System::account_nonce(2), 0);
		});
	}

	#[test]
	fn item_is_bound_to_mode_submitter_and_nonce() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_transfer(4, 100), SetOrigin::signed(1)),
				spec(call_transfer(4, 100), SetOrigin::signed(2)),
			];
			// Signed for submitter 3's batch with nonce 1, in `Stop` mode.
			let items = build_items(3, 1, BatchMode::Stop, &specs);

			// Submitted by 3 with nonce 0.
			apply_ok(signed_tx(3, batch_call(BatchMode::Stop, items.clone())));
			assert_eq!(System::account_nonce(3), 1);
			// Submitted by 5 with nonce 1.
			assert_ok!(apply(signed_tx(5, call_transfer(4, 1))).unwrap());
			assert_eq!(System::account_nonce(5), 1);
			apply_ok(signed_tx(5, batch_call(BatchMode::Stop, items.clone())));
			// Submitted by 3 with nonce 1, in `Continue` mode.
			apply_ok(signed_tx(3, batch_call(BatchMode::Continue, items.clone())));
			assert_eq!(
				pallet_events(),
				vec![
					Event::BatchInterrupted {
						index: 0,
						error: invalid(InvalidTransaction::BadProof)
					},
					Event::BatchInterrupted {
						index: 0,
						error: invalid(InvalidTransaction::BadProof)
					},
					Event::ItemFailed { index: 0, error: invalid(InvalidTransaction::BadProof) },
					Event::ItemFailed { index: 1, error: invalid(InvalidTransaction::BadProof) },
					Event::BatchCompletedWithErrors,
				]
			);
			assert_eq!(balance(4), INITIAL_BALANCE + 1);

			// Submitted by 3 with nonce 2 now, which is not what the items were signed for.
			apply_ok(signed_tx(3, batch_call(BatchMode::Stop, items.clone())));
			assert_eq!(
				pallet_events().last(),
				Some(&Event::BatchInterrupted {
					index: 0,
					error: invalid(InvalidTransaction::BadProof)
				})
			);

			// Signed for exactly this batch.
			let items = build_items(3, 3, BatchMode::Stop, &specs);
			apply_ok(signed_tx(3, batch_call(BatchMode::Stop, items)));
			assert_eq!(pallet_events().last(), Some(&Event::BatchCompleted));
			assert_eq!(balance(4), INITIAL_BALANCE + 201);
		});
	}

	#[test]
	fn items_cannot_nest_batch_calls() {
		new_test_ext().execute_with(|| {
			let inner = batch_call(
				BatchMode::Stop,
				build_items(3, 0, BatchMode::Stop, &[spec(call_remark(), SetOrigin::signed(1))]),
			);
			// Directly: the transaction is invalid.
			for mode in [BatchMode::Stop, BatchMode::Continue] {
				let specs = [spec(inner.clone(), SetOrigin::signed(1))];
				let uxt = batch_tx(3, BatchMode::Stop, &specs);
				assert_eq!(validate(uxt.clone()), Err(InvalidTransaction::Call.into()));
				assert_eq!(apply(uxt), Err(InvalidTransaction::Call.into()));
				let uxt = batch_tx(3, mode, &specs);
				assert_eq!(apply(uxt), Err(InvalidTransaction::Call.into()));
			}
			// Nested in another call: filtered at dispatch, the item fails.
			let nested = RuntimeCall::Utility(UtilityCall::batch_all { calls: vec![inner] });
			let specs = [spec(nested, SetOrigin::signed(1))];
			apply_ok(batch_tx(3, BatchMode::Stop, &specs));
			assert_eq!(
				pallet_events().last(),
				Some(&Event::BatchInterrupted {
					index: 0,
					error: failed(frame_system::Error::<Test>::CallFiltered),
				})
			);
			assert_eq!(System::account_nonce(1), 1);
		});
	}

	#[test]
	fn filtered_calls_are_rejected() {
		new_test_ext().execute_with(|| {
			let noop = RuntimeCall::Example(ExampleCall::noop { weight: Weight::from_parts(1, 0) });
			// Directly: the transaction is invalid.
			let specs = [spec(noop.clone(), SetOrigin::signed(1))];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			assert_eq!(validate(uxt.clone()), Err(InvalidTransaction::Call.into()));
			assert_eq!(apply(uxt), Err(InvalidTransaction::Call.into()));
			// Nested: the item fails.
			let nested = RuntimeCall::Utility(UtilityCall::batch_all { calls: vec![noop] });
			let specs = [spec(nested, SetOrigin::signed(1))];
			apply_ok(batch_tx(3, BatchMode::Stop, &specs));
			assert_eq!(
				pallet_events().last(),
				Some(&Event::BatchInterrupted {
					index: 0,
					error: failed(frame_system::Error::<Test>::CallFiltered),
				})
			);
		});
	}

	#[test]
	fn non_normal_items_are_rejected() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_remark(), SetOrigin::signed(1)),
				spec(RuntimeCall::Example(ExampleCall::operational {}), SetOrigin::signed(2)),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			assert_eq!(uxt.get_dispatch_info().class, DispatchClass::Normal);
			assert_eq!(validate(uxt.clone()), Err(InvalidTransaction::Call.into()));
			assert_eq!(apply(uxt), Err(InvalidTransaction::Call.into()));
		});
	}

	#[test]
	fn empty_batch_is_rejected() {
		new_test_ext().execute_with(|| {
			for mode in [BatchMode::Stop, BatchMode::Continue] {
				let uxt = batch_tx(3, mode, &[]);
				assert_eq!(validate(uxt.clone()), Err(InvalidTransaction::Call.into()));
				assert_eq!(apply(uxt), Err(InvalidTransaction::Call.into()));
			}
		});
	}

	#[test]
	fn batch_requires_a_signed_submitter() {
		new_test_ext().execute_with(|| {
			let call = batch_call(
				BatchMode::Stop,
				build_items(3, 0, BatchMode::Stop, &[spec(call_remark(), SetOrigin::signed(1))]),
			);
			// A general transaction has no signer.
			let uxt = UncheckedExtrinsic::new_transaction(call.clone(), tx_ext(0));
			assert_eq!(validate(uxt.clone()), Err(InvalidTransaction::BadSigner.into()));
			assert_eq!(apply(uxt), Err(InvalidTransaction::BadSigner.into()));
			// A bare one skips the pipeline and the call rejects its origin.
			let uxt = UncheckedExtrinsic::new_bare(call);
			assert_eq!(apply(uxt).unwrap().map_err(|e| e.error), Err(BadOrigin.into()));
			assert_eq!(System::account_nonce(1), 0);
		});
	}

	#[test]
	fn call_requires_the_batch_origin() {
		new_test_ext().execute_with(|| {
			let items: MultiOriginItemsOf<Test> =
				build_items(3, 0, BatchMode::Stop, &[spec(call_remark(), SetOrigin::signed(1))])
					.try_into()
					.unwrap();
			assert_noop!(
				UtilityExt::batch_multi_origin(RuntimeOrigin::signed(3), items.clone()),
				BadOrigin
			);
			assert_noop!(
				UtilityExt::force_batch_multi_origin(RuntimeOrigin::root(), items.clone()),
				BadOrigin
			);
			assert_noop!(
				UtilityExt::batch_multi_origin(RuntimeOrigin::none(), items.clone()),
				BadOrigin
			);
			// Wrapped in another call, the batch call does not get the origin either.
			let wrapped = RuntimeCall::Utility(UtilityCall::batch_all {
				calls: vec![batch_call(BatchMode::Stop, items.to_vec())],
			});
			assert_eq!(
				wrapped.clone().dispatch(RuntimeOrigin::signed(3)).map_err(|e| e.error),
				Err(BadOrigin.into())
			);
			assert_eq!(
				apply(signed_tx(3, wrapped)).unwrap().map_err(|e| e.error),
				Err(BadOrigin.into())
			);

			// The extension provides it.
			let call = batch_call(BatchMode::Stop, items.to_vec());
			let origin: RuntimeOrigin =
				RawOrigin::MultiOriginBatch { submitter: 3, nonce: 0 }.into();
			assert_ok!(call.dispatch(origin));
			assert_eq!(System::account_nonce(1), 1);
		});
	}

	#[test]
	fn extension_passes_through_other_transactions() {
		new_test_ext().execute_with(|| {
			let call = call_transfer(4, 100);
			let uxt = signed_tx(1, call.clone());
			let info = uxt.get_dispatch_info();
			let len = uxt.encoded_size();
			let validity = validate(uxt.clone()).unwrap();
			assert_eq!(MultiOriginBatch::<Test>::new().weight(&call), Weight::zero());

			// Regular fee and priority; the batch extension weighs nothing here.
			let post_info = apply(uxt).unwrap().unwrap();
			assert_eq!(balance(1), INITIAL_BALANCE - 100 - fee(info.total_weight(), len));
			assert_eq!(post_info.actual_weight, Some(info.total_weight()));
			assert_eq!(
				validity.priority,
				ChargeTransactionPayment::<Test>::get_priority(&info, len, 0, 0)
			);
			assert_eq!(System::account_nonce(1), 1);
			assert_fee_credit_empty();

			// The wrapped extension is still skipped for calls it skips.
			let call = RuntimeCall::Example(ExampleCall::free { err: false });
			let uxt = signed_tx(2, call);
			assert_ok!(apply(uxt).unwrap());
			assert_eq!(balance(2), INITIAL_BALANCE);
		});
	}

	#[test]
	fn batch_priority_is_scaled_to_its_full_weight() {
		new_test_ext().execute_with(|| {
			// Heavy enough for weight, not length, to limit how many such batches fit a block.
			let specs =
				[spec(call_foobar(false, 10_000_000_000_000_000, None), SetOrigin::signed(1))];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let tip = 0;
			let info = uxt.get_dispatch_info();
			let len = uxt.encoded_size();
			let (items, mode) = Pallet::<Test>::batch_items(&uxt.function).unwrap();
			let share = DispatchInfo {
				call_weight: Pallet::<Test>::submitter_weight(items, mode),
				..info.clone()
			};

			let validity = validate(uxt).unwrap();

			let fee = TransactionPayment::compute_fee(len as u32, &share, tip);
			let share_priority =
				ChargeTransactionPayment::<Test>::get_priority(&share, len, tip, fee);
			let full_priority =
				ChargeTransactionPayment::<Test>::get_priority(&info, len, tip, fee);
			assert!(share_priority > full_priority);
			assert_eq!(validity.priority, full_priority);
			assert!(validity.priority > 0);
		});
	}

	#[test]
	fn item_whose_post_dispatch_fails_is_rolled_back_and_booked() {
		new_test_ext().execute_with(|| {
			SetOrigin::fail_post_dispatch();
			let specs = [spec(call_transfer(4, 100), SetOrigin::signed(1))];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let submitter_fee = submitter_fee(&uxt);
			let pipelines = pipelines_weight(&uxt);
			let outer = outer_weight(&uxt);

			let post_info = apply_ok(uxt);

			// The call ran and was rolled back with the item.
			assert_eq!(balance(4), INITIAL_BALANCE);
			assert_eq!(balance(1), INITIAL_BALANCE);
			assert_eq!(System::account_nonce(1), 0);
			assert_eq!(SetOrigin::post_dispatched(), 0);
			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			assert_eq!(
				pallet_events(),
				vec![Event::BatchInterrupted {
					index: 0,
					error: invalid(SET_ORIGIN_POST_DISPATCH_ERROR)
				}]
			);
			// Nobody paid for the call, but the block accounts for it at its worst case.
			let overhead = <Test as Config>::WeightInfo::batch_multi_origin(1);
			assert_eq!(
				post_info.actual_weight,
				Some(
					overhead
						.saturating_add(pipelines)
						.saturating_add(specs[0].call.get_dispatch_info().call_weight)
						.saturating_add(outer)
				)
			);
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn item_implication_encoding_is_stable() {
		// Wallets build this payload themselves: prefix, mode, submitter, nonce, index, hash of
		// the SCALE encoded list of `(call, origin)` pairs.
		let call = call_remark();
		let origin = signed_by(1);
		let items_hash = Pallet::<Test>::items_hash([(&call, &origin), (&call, &origin)]);
		assert_eq!(
			items_hash,
			sp_io::hashing::blake2_256(&vec![(&call, &origin), (&call, &origin)].encode()).into()
		);
		let implication = ItemImplication {
			mode: BatchMode::Continue,
			submitter: &0x0102030405060708u64,
			nonce: 9u32,
			index: 2,
			items_hash: &items_hash,
		};
		let mut expected = ITEM_IMPLICATION_PREFIX.to_vec();
		expected.push(1); // `BatchMode::Continue`
		expected.extend(0x0102030405060708u64.encode());
		expected.extend(9u32.encode());
		expected.extend(2u32.encode());
		expected.extend(items_hash.encode());
		assert_eq!(implication.encode(), expected);
		assert_eq!(&expected[..8], b"_mbatch_");
	}

	#[test]
	fn fee_payment_extension_must_come_after_the_batch_extension() {
		type Misordered = (
			frame_system::CheckNonce<Test>,
			frame_system::CheckWeight<Test>,
			ChargeTransactionPayment<Test>,
			MultiOriginBatch<Test>,
		);
		type MisorderedExtrinsic =
			sp_runtime::generic::UncheckedExtrinsic<u64, RuntimeCall, TestSignature, Misordered>;
		new_test_ext().execute_with(|| {
			let specs = [spec(call_transfer(4, 100), SetOrigin::signed(1))];
			let call = batch_call(BatchMode::Stop, build_items(3, 0, BatchMode::Stop, &specs));
			let ext: Misordered = (
				frame_system::CheckNonce::from(0),
				frame_system::CheckWeight::new(),
				ChargeTransactionPayment::from(0),
				MultiOriginBatch::new(),
			);
			let payload = SignedPayload::new(call.clone(), ext.clone())
				.unwrap()
				.using_encoded(|payload| payload.to_vec());
			let uxt = MisorderedExtrinsic::new_signed(call, 3, TestSignature(3, payload), ext);
			let info = uxt.get_dispatch_info();
			let len = uxt.encoded_size();
			let xt = <MisorderedExtrinsic as Checkable<IdentityLookup<u64>>>::check(
				uxt,
				&Default::default(),
			)
			.unwrap();

			// The fee payment extension charged the full fee first: rejected.
			assert_eq!(xt.apply::<Test>(&info, len), Err(InvalidTransaction::Payment.into()));
			assert_eq!(balance(4), INITIAL_BALANCE);
		});
	}

	#[test]
	fn extension_must_come_after_check_nonce() {
		type Misordered = (
			MultiOriginBatch<Test>,
			frame_system::CheckNonce<Test>,
			frame_system::CheckWeight<Test>,
			ChargeTransactionPayment<Test>,
		);
		type MisorderedExtrinsic =
			sp_runtime::generic::UncheckedExtrinsic<u64, RuntimeCall, TestSignature, Misordered>;
		new_test_ext().execute_with(|| {
			let specs = [spec(call_transfer(4, 100), SetOrigin::signed(1))];
			let call = batch_call(BatchMode::Stop, build_items(3, 0, BatchMode::Stop, &specs));
			let ext: Misordered = (
				MultiOriginBatch::new(),
				frame_system::CheckNonce::from(0),
				frame_system::CheckWeight::new(),
				ChargeTransactionPayment::from(0),
			);
			let payload = SignedPayload::new(call.clone(), ext.clone())
				.unwrap()
				.using_encoded(|payload| payload.to_vec());
			let uxt = MisorderedExtrinsic::new_signed(call, 3, TestSignature(3, payload), ext);
			let info = uxt.get_dispatch_info();
			let len = uxt.encoded_size();
			let xt = <MisorderedExtrinsic as Checkable<IdentityLookup<u64>>>::check(
				uxt,
				&Default::default(),
			)
			.unwrap();

			// `CheckNonce` sees the batch origin, so it checks and bumps nothing: the batch would
			// be replayable and is rejected instead.
			assert_eq!(xt.apply::<Test>(&info, len), Err(InvalidTransaction::BadSigner.into()));
			assert_eq!(System::account_nonce(1), 0);
			assert_eq!(balance(4), INITIAL_BALANCE);
		});
	}

	#[test]
	fn pays_no_items_cost_nobody() {
		new_test_ext().execute_with(|| {
			// Two free items, one of which fails, and a paying one.
			let specs = [
				spec(RuntimeCall::Example(ExampleCall::free { err: false }), SetOrigin::signed(1)),
				spec(RuntimeCall::Example(ExampleCall::free { err: true }), SetOrigin::signed(2)),
				with_nonce(spec(call_foobar(false, 1_000, None), SetOrigin::signed(1)), 1),
			];
			let uxt = batch_tx(3, BatchMode::Continue, &specs);
			let info = uxt.get_dispatch_info();
			let len = uxt.encoded_size();
			let full_share_fee = submitter_fee(&uxt);
			assert_eq!(info.pays_fee, Pays::Yes);
			let (items, mode) = Pallet::<Test>::batch_items(&uxt.function).unwrap();
			// The free items' pipelines and bytes come off the submitter's share.
			let free_weight = items[0].extension.weight(&items[0].call) +
				items[1].extension.weight(&items[1].call);
			let free_len = items[0].encoded_size() + items[1].encoded_size();
			let share = Pallet::<Test>::submitter_weight(items, mode)
				.saturating_add(info.extension_weight)
				.saturating_sub(free_weight);
			let submitter_fee = fee(share, len - free_len);
			assert!(submitter_fee < full_share_fee);

			apply_ok(uxt);

			assert_eq!(balance(1), INITIAL_BALANCE - 1_000);
			assert_eq!(balance(2), INITIAL_BALANCE);
			assert_eq!(System::account_nonce(1), 2);
			assert_eq!(System::account_nonce(2), 1);
			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			System::assert_has_event(
				pallet_transaction_payment::Event::<Test>::TransactionFeePaid {
					who: 3,
					actual_fee: submitter_fee,
					tip: 0,
				}
				.into(),
			);
			assert_eq!(pallet_events().last(), Some(&Event::BatchCompletedWithErrors));
			assert!(RefundableShare::<Test>::get().is_none());
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn free_items_are_refunded_when_the_batch_stops() {
		new_test_ext().execute_with(|| {
			// A free item, then an invalid one which stops the batch.
			let specs = [
				spec(RuntimeCall::Example(ExampleCall::free { err: false }), SetOrigin::signed(1)),
				with_nonce(spec(call_transfer(4, 100), SetOrigin::signed(2)), 5),
				spec(call_foobar(false, 1_000, None), SetOrigin::signed(1)),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let info = uxt.get_dispatch_info();
			let len = uxt.encoded_size();
			let (items, mode) = Pallet::<Test>::batch_items(&uxt.function).unwrap();
			let share = Pallet::<Test>::submitter_weight(items, mode)
				.saturating_add(info.extension_weight)
				.saturating_sub(items[0].extension.weight(&items[0].call));
			let submitter_fee = fee(share, len - items[0].encoded_size());

			apply_ok(uxt);

			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			assert_eq!(
				pallet_events().last(),
				Some(&Event::BatchInterrupted {
					index: 1,
					error: invalid(InvalidTransaction::Future)
				})
			);
			assert!(RefundableShare::<Test>::get().is_none());
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn stale_refundable_share_is_ignored() {
		new_test_ext().execute_with(|| {
			// Left behind by a dispatch which did not go through the extension.
			RefundableShare::<Test>::put((Weight::MAX, u32::MAX));
			let specs = [spec(call_foobar(false, 1_000, None), SetOrigin::signed(1))];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let submitter_fee = submitter_fee(&uxt);

			apply_ok(uxt);

			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			assert!(RefundableShare::<Test>::get().is_none());
		});
	}

	#[test]
	fn zero_fee_batch_parks_nothing() {
		new_test_ext().execute_with(|| {
			make_fees_free();
			let specs = [
				spec(call_transfer(4, 100), SetOrigin::signed(1)),
				spec(call_transfer(4, 200), SetOrigin::signed(2)),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let info = uxt.get_dispatch_info();
			assert_eq!(TransactionPayment::compute_fee(uxt.encoded_size() as u32, &info, 0), 0);

			// Nothing is withdrawn, so there is no credit to park and none to settle.
			apply_ok(uxt);

			assert_eq!(balance(4), INITIAL_BALANCE + 300);
			assert_eq!(balance(1), INITIAL_BALANCE - 100);
			assert_eq!(balance(2), INITIAL_BALANCE - 200);
			assert_eq!(balance(3), INITIAL_BALANCE);
			assert_eq!(pallet_events().last(), Some(&Event::BatchCompleted));
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn submitter_who_cannot_pay_in_prepare_is_rejected() {
		use frame_support::traits::Currency;
		use sp_runtime::{
			generic::{CheckedExtrinsic, ExtrinsicFormat},
			traits::TxBaseImplication,
		};
		new_test_ext().execute_with(|| {
			let specs = [spec(call_transfer(4, 100), SetOrigin::signed(1))];
			let (xt, info, len) = check(batch_tx(3, BatchMode::Stop, &specs));
			let CheckedExtrinsic { format: ExtrinsicFormat::Signed(submitter, ext), function } = xt
			else {
				panic!("the batch is signed")
			};
			let (_, val, origin) = ext
				.validate(
					RuntimeOrigin::signed(submitter),
					&function,
					&info,
					len,
					ext.implicit().expect("implicit data is available"),
					&TxBaseImplication(&function),
					TransactionSource::External,
				)
				.expect("the submitter can pay");

			// The submitter's funds go away between validation and preparation.
			Balances::make_free_balance_be(&3, 1);
			assert_eq!(
				ext.prepare(val, &origin, &function, &info, len).map(|_| ()).unwrap_err(),
				InvalidTransaction::Payment.into()
			);

			// Nothing ran and nothing was withdrawn.
			assert_eq!(balance(3), 1);
			assert_eq!(balance(4), INITIAL_BALANCE);
			assert_eq!(SetOrigin::prepared(), 0);
			assert!(pallet_events().is_empty());
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn wallets_get_the_signing_payload_and_the_share() {
		new_test_ext().execute_with(|| {
			let specs = [
				spec(call_transfer(4, 100), SetOrigin::signed(1)),
				spec(call_transfer(4, 100), SetOrigin::signed(2)),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let (items, mode) = Pallet::<Test>::batch_items(&uxt.function).expect("a batch");
			let pairs = || items.iter().map(|item| (&item.call, &item.origin));
			let items_hash = Pallet::<Test>::items_hash(pairs());
			for (index, item) in items.iter().enumerate() {
				let index = index as u32;
				let implication = ItemImplication {
					mode,
					submitter: &3u64,
					nonce: 0u32,
					index,
					items_hash: &items_hash,
				};
				let payload = |authorizer| {
					Pallet::<Test>::item_signing_payload(
						mode,
						&3,
						0,
						index,
						pairs(),
						&item.extension,
						authorizer,
					)
				};
				let (_, set_origin, authorize, nonce, payment) = item.extension.clone();
				// The first extension sees the rest of the pipeline, which has no implicit data.
				let mut expected = implication.encode();
				expected.extend((&set_origin, &authorize, &nonce, &payment).encode());
				assert_eq!(payload(0), Some(expected));
				// The last one sees the implication alone.
				assert_eq!(payload(4), Some(implication.encode()));
				assert_eq!(payload(5), None);

				let extensions =
					Pallet::<Test>::item_extensions(&item.extension).expect("implicit available");
				assert_eq!(extensions.len(), 5);
				assert_eq!(extensions[3].identifier, "CheckNonce");
				assert_eq!(extensions[3].explicit, nonce.encode());
				assert!(extensions.iter().all(|extension| extension.implicit.is_empty()));
			}

			let len = uxt.encoded_size() as u32;
			let share = MultiOriginBatch::<Test>::query_share_info(&uxt, len).expect("a batch");
			assert_eq!(share.partial_fee, submitter_fee(&uxt));
			assert_eq!(
				share.weight,
				Pallet::<Test>::submitter_weight(items, mode) +
					uxt.get_dispatch_info().extension_weight
			);
			let other = signed_tx(1, call_transfer(4, 1));
			assert_eq!(MultiOriginBatch::<Test>::query_share_info(&other, 0), None);
		});
	}

	#[test]
	fn submitter_fee_waits_in_the_extension_while_items_pay() {
		new_test_ext().execute_with(|| {
			// Items settle their own payments and find no credit of the submitter's to take.
			let specs = [
				spec(call_foobar(false, 1_000, Some(400)), SetOrigin::signed(1)),
				spec(call_foobar(false, 2_000, Some(500)), SetOrigin::signed(2)),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let submitter_fee = submitter_fee(&uxt);

			apply_ok(uxt);

			assert_eq!(balance(1), INITIAL_BALANCE - 400);
			assert_eq!(balance(2), INITIAL_BALANCE - 500);
			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			assert_fee_credit_empty();
		});
	}

	#[test]
	fn authorization_is_checked_against_earlier_items() {
		new_test_ext().execute_with(|| {
			let claim = RuntimeCall::Example(ExampleCall::claim {});
			let specs = [authorized(claim.clone()), authorized(claim)];
			apply_ok(batch_tx(3, BatchMode::Stop, &specs));

			// The first claim applied, the second was authorized against the state it left.
			assert_eq!(example::Claims::<Test>::get(), 1);
			assert_eq!(
				pallet_events(),
				vec![
					Event::ItemCompleted { index: 0 },
					Event::BatchInterrupted { index: 1, error: invalid(InvalidTransaction::Stale) },
				]
			);
		});
	}

	#[test]
	fn items_are_not_validated_in_the_pool() {
		new_test_ext().execute_with(|| {
			// Invalid items, failing items and unauthorized items all validate.
			let specs = [
				with_nonce(spec(call_transfer(4, 100), SetOrigin::signed(1)), 9),
				spec(call_foobar(true, 1_000, None), SetOrigin::signed(2)),
				spec(call_remark(), SetOrigin::none()),
			];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			assert_ok!(validate(uxt.clone()));
			assert_eq!(SetOrigin::prepared(), 0);
			assert_eq!(System::account_nonce(1), 0);

			// A submitter who cannot pay does not.
			assert_ok!(Balances::force_set_balance(RuntimeOrigin::root(), 3, 1));
			assert_eq!(validate(uxt), Err(InvalidTransaction::Payment.into()));
		});
	}

	#[test]
	fn item_origin_can_be_any_pallets_origin() {
		new_test_ext().execute_with(|| {
			// A council item costs nothing: there is no account to charge.
			let specs =
				[spec(RuntimeCall::Example(ExampleCall::council_only {}), SetOrigin::council())];
			let uxt = batch_tx(3, BatchMode::Stop, &specs);
			let submitter_fee = submitter_fee(&uxt);
			apply_ok(uxt);
			assert_eq!(example::CouncilCalls::<Test>::get(), 1);
			assert_eq!(balance(3), INITIAL_BALANCE - submitter_fee);
			assert_fee_credit_empty();
		});
	}
}
