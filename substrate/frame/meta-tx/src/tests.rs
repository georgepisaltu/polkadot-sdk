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

use crate::*;
use frame_support::{assert_ok, traits::tokens::fungible::Inspect};
use keyring::AccountKeyring;
use mock::*;
use sp_io::hashing::blake2_256;
use sp_runtime::{
	traits::{Applyable, Checkable, Hash, IdentityLookup, TransactionExtensionBase},
	MultiSignature,
};

#[docify::export]
#[test]
fn sign_and_execute_meta_tx() {
	new_test_ext().execute_with(|| {
		// meta tx signer
		let alice_keyring = AccountKeyring::Alice;
		// meta tx relayer
		let bob_keyring = AccountKeyring::Bob;

		let alice_account = AccountId::from(alice_keyring.public());
		let bob_account = AccountId::from(bob_keyring.public());

		let ed = Balances::minimum_balance();
		let tx_fee: Balance = (2 * TX_FEE).into(); // base tx fee + weight fee
		let alice_balance = ed * 100;
		let bob_balance = ed * 100;

		{
			// setup initial balances for alice and bob
			Balances::force_set_balance(
				RuntimeOrigin::root(),
				alice_account.clone().into(),
				alice_balance,
			)
			.unwrap();
			Balances::force_set_balance(
				RuntimeOrigin::root(),
				bob_account.clone().into(),
				bob_balance,
			)
			.unwrap();
		}

		// Alice builds a meta transaction.

		let remark_call =
			RuntimeCall::System(frame_system::Call::remark_with_event { remark: vec![1] });

		let genesis_hash = System::block_hash(0);
		let meta_tx = MetaTxFor::<Runtime>::new(
			alice_account.clone(),
			remark_call.clone(),
			0,
			genesis_hash,
			0,
		);

		let meta_tx_sig = MultiSignature::Sr25519(meta_tx.using_encoded(|e| alice_keyring.sign(e)));

		// Encode and share with the world.
		let meta_tx_with_sig_encoded = (meta_tx, meta_tx_sig).encode();

		// Bob acts as meta transaction relayer.

		let (meta_tx, meta_tx_sig): (MetaTxFor<Runtime>, MultiSignature) =
			Decode::decode(&mut &meta_tx_with_sig_encoded[..]).unwrap();
		let call = RuntimeCall::MetaTx(Call::dispatch {
			meta_tx: meta_tx.clone(),
			proof: Proof::Signed(meta_tx_sig.clone()),
		});
		let tx_ext: Extension = (
			frame_system::CheckNonZeroSender::<Runtime>::new(),
			frame_system::CheckSpecVersion::<Runtime>::new(),
			frame_system::CheckTxVersion::<Runtime>::new(),
			frame_system::CheckGenesis::<Runtime>::new(),
			frame_system::CheckMortality::<Runtime>::from(sp_runtime::generic::Era::immortal()),
			frame_system::CheckNonce::<Runtime>::from(
				frame_system::Pallet::<Runtime>::account(&bob_account).nonce,
			),
			frame_system::CheckWeight::<Runtime>::new(),
			pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0),
		);

		let tx_sig = MultiSignature::Sr25519(
			(call.clone(), tx_ext.clone(), tx_ext.implicit().unwrap())
				.using_encoded(|e| bob_keyring.sign(&blake2_256(e))),
		);

		let uxt = UncheckedExtrinsic::new_signed(call, bob_account.clone(), tx_sig, tx_ext);

		// Check Extrinsic validity and apply it.

		let uxt_info = uxt.get_dispatch_info();
		let uxt_len = uxt.using_encoded(|e| e.len());

		let xt = <UncheckedExtrinsic as Checkable<IdentityLookup<AccountId>>>::check(
			uxt,
			&Default::default(),
		)
		.unwrap();

		let res = xt.apply::<Runtime>(&uxt_info, uxt_len).unwrap();

		// Asserting the results.

		assert!(res.is_ok());

		System::assert_has_event(RuntimeEvent::MetaTx(crate::Event::Dispatched { result: res }));

		System::assert_has_event(RuntimeEvent::System(frame_system::Event::Remarked {
			sender: alice_account.clone(),
			hash: <Runtime as frame_system::Config>::Hashing::hash(&[1]),
		}));

		// Alice balance is unchanged, Bob paid the transaction fee.
		assert_eq!(alice_balance, Balances::free_balance(&alice_account));
		assert_eq!(bob_balance - tx_fee, Balances::free_balance(bob_account));
		assert_eq!(System::account_nonce(&alice_account), 1);
	});
}

#[test]
fn multiple_signers_meta_tx() {
	new_test_ext().execute_with(|| {
		// meta tx signer
		let alice_keyring = AccountKeyring::Alice;
		// meta tx signer
		let bob_keyring = AccountKeyring::Bob;
		// meta tx signer
		let charlie_keyring = AccountKeyring::Charlie;
		// meta tx relayer
		let dave_keyring = AccountKeyring::Dave;

		let alice_account = AccountId::from(alice_keyring.public());
		let bob_account = AccountId::from(bob_keyring.public());
		let charlie_account = AccountId::from(charlie_keyring.public());
		let dave_account = AccountId::from(dave_keyring.public());

		let ed = Balances::minimum_balance();
		let tx_fee: Balance = (2 * TX_FEE).into(); // base tx fee + weight fee
		let alice_balance = ed * 100;
		let bob_balance = ed * 100;
		let charlie_balance = ed * 100;
		let dave_balance = ed * 100;

		{
			// setup initial balances for alice, bob, charlie and dave
			Balances::force_set_balance(
				RuntimeOrigin::root(),
				alice_account.clone().into(),
				alice_balance,
			)
			.unwrap();
			Balances::force_set_balance(
				RuntimeOrigin::root(),
				bob_account.clone().into(),
				bob_balance,
			)
			.unwrap();
			Balances::force_set_balance(
				RuntimeOrigin::root(),
				charlie_account.clone().into(),
				charlie_balance,
			)
			.unwrap();
			Balances::force_set_balance(
				RuntimeOrigin::root(),
				dave_account.clone().into(),
				dave_balance,
			)
			.unwrap();
		}

		// Alice, Bob and Charlie build their meta transactions.

		let alice_call =
			RuntimeCall::System(frame_system::Call::remark_with_event { remark: vec![1] });
		let bob_call =
			RuntimeCall::System(frame_system::Call::remark_with_event { remark: vec![2] });
		let charlie_call =
			RuntimeCall::System(frame_system::Call::remark_with_event { remark: vec![3] });

		let genesis_hash = System::block_hash(0);
		let alice_meta_tx = MetaTxFor::<Runtime>::new(
			alice_account.clone(),
			alice_call.clone(),
			0,
			genesis_hash,
			0,
		);
		let bob_meta_tx =
			MetaTxFor::<Runtime>::new(bob_account.clone(), bob_call.clone(), 0, genesis_hash, 0);
		let charlie_meta_tx = MetaTxFor::<Runtime>::new(
			charlie_account.clone(),
			charlie_call.clone(),
			0,
			genesis_hash,
			0,
		);

		let meta_txs = vec![alice_meta_tx, bob_meta_tx, charlie_meta_tx];
		let payload = crate::Pallet::<Runtime>::create_multisigner_payload(&meta_txs[..]).unwrap();

		let alice_sig = MultiSignature::Sr25519(alice_keyring.sign(&payload));
		let bob_sig = MultiSignature::Sr25519(bob_keyring.sign(&payload));
		let charlie_sig = MultiSignature::Sr25519(charlie_keyring.sign(&payload));
		let mut sigs = vec![
			(alice_account.clone(), alice_sig),
			(bob_account.clone(), bob_sig),
			(charlie_account.clone(), charlie_sig),
		];
		sigs.sort_by_key(|(account, _)| account.clone());
		let sigs: Vec<MultiSignature> = sigs.into_iter().map(|(_, sig)| sig).collect();

		// Encode and share with the world.
		let meta_txs_with_sigs_encoded = (meta_txs, sigs).encode();

		// Dave acts as meta transaction relayer.
		let (meta_txs, meta_tx_sigs): (Vec<MetaTxFor<Runtime>>, Vec<MultiSignature>) =
			Decode::decode(&mut &meta_txs_with_sigs_encoded[..]).unwrap();
		let proofs: Vec<ProofFor<Runtime>> =
			meta_tx_sigs.iter().cloned().map(|sig| Proof::Signed(sig)).collect();
		let call =
			RuntimeCall::MetaTx(Call::dispatch_multisigner { meta_txs: meta_txs.clone(), proofs });
		let tx_ext: Extension = (
			frame_system::CheckNonZeroSender::<Runtime>::new(),
			frame_system::CheckSpecVersion::<Runtime>::new(),
			frame_system::CheckTxVersion::<Runtime>::new(),
			frame_system::CheckGenesis::<Runtime>::new(),
			frame_system::CheckMortality::<Runtime>::from(sp_runtime::generic::Era::immortal()),
			frame_system::CheckNonce::<Runtime>::from(
				frame_system::Pallet::<Runtime>::account(&dave_account).nonce,
			),
			frame_system::CheckWeight::<Runtime>::new(),
			pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0),
		);

		let tx_sig = MultiSignature::Sr25519(
			(call.clone(), tx_ext.clone(), tx_ext.implicit().unwrap())
				.using_encoded(|e| dave_keyring.sign(&blake2_256(e))),
		);

		let uxt = UncheckedExtrinsic::new_signed(call, dave_account.clone(), tx_sig, tx_ext);

		// Check Extrinsic validity and apply it.

		let uxt_info = uxt.get_dispatch_info();
		let uxt_len = uxt.using_encoded(|e| e.len());

		let xt = <UncheckedExtrinsic as Checkable<IdentityLookup<AccountId>>>::check(
			uxt,
			&Default::default(),
		)
		.unwrap();

		let res = xt.apply::<Runtime>(&uxt_info, uxt_len).unwrap();

		// Asserting the results.

		assert!(res.is_ok());

		System::assert_has_event(RuntimeEvent::System(frame_system::Event::Remarked {
			sender: alice_account.clone(),
			hash: <Runtime as frame_system::Config>::Hashing::hash(&[1]),
		}));
		System::assert_has_event(RuntimeEvent::System(frame_system::Event::Remarked {
			sender: bob_account.clone(),
			hash: <Runtime as frame_system::Config>::Hashing::hash(&[2]),
		}));
		System::assert_has_event(RuntimeEvent::System(frame_system::Event::Remarked {
			sender: charlie_account.clone(),
			hash: <Runtime as frame_system::Config>::Hashing::hash(&[3]),
		}));

		// Alice, Bob and Charlie didn't pay, Dave paid the transaction fee.
		assert_eq!(alice_balance, Balances::free_balance(&alice_account));
		assert_eq!(bob_balance, Balances::free_balance(&bob_account));
		assert_eq!(charlie_balance, Balances::free_balance(&charlie_account));
		assert_eq!(dave_balance - tx_fee, Balances::free_balance(&dave_account));
		assert_eq!(System::account_nonce(&alice_account), 1);
		assert_eq!(System::account_nonce(&bob_account), 1);
		assert_eq!(System::account_nonce(&charlie_account), 1);
		assert_eq!(System::account_nonce(&dave_account), 1);
	});
}

#[test]
fn three_way_transfer_meta_tx() {
	new_test_ext().execute_with(|| {
		// meta tx signer
		let alice_keyring = AccountKeyring::Alice;
		// meta tx signer
		let bob_keyring = AccountKeyring::Bob;
		// meta tx signer
		let charlie_keyring = AccountKeyring::Charlie;
		// meta tx relayer
		let dave_keyring = AccountKeyring::Dave;

		let alice_account = AccountId::from(alice_keyring.public());
		let bob_account = AccountId::from(bob_keyring.public());
		let charlie_account = AccountId::from(charlie_keyring.public());
		let dave_account = AccountId::from(dave_keyring.public());

		let ed = Balances::minimum_balance();
		let tx_fee: Balance = (2 * TX_FEE).into(); // base tx fee + weight fee
		let alice_balance = ed * 1000;
		let bob_balance = ed * 1000;
		let charlie_balance = ed * 1000;
		let dave_balance = ed * 1000;

		{
			// setup initial balances for alice, bob, charlie and dave
			Balances::force_set_balance(
				RuntimeOrigin::root(),
				alice_account.clone().into(),
				alice_balance,
			)
			.unwrap();
			Balances::force_set_balance(
				RuntimeOrigin::root(),
				bob_account.clone().into(),
				bob_balance,
			)
			.unwrap();
			Balances::force_set_balance(
				RuntimeOrigin::root(),
				charlie_account.clone().into(),
				charlie_balance,
			)
			.unwrap();
			Balances::force_set_balance(
				RuntimeOrigin::root(),
				dave_account.clone().into(),
				dave_balance,
			)
			.unwrap();
		}

		// Create 2 assets with Dave as the owner and endow Bob and Charlie with one each.
		let bob_asset_0_balance = 1000;
		let charlie_asset_1_balance = 1000;
		assert_ok!(Assets::force_create(RuntimeOrigin::root(), 0, dave_account.clone(), false, 1));
		assert_ok!(Assets::force_create(RuntimeOrigin::root(), 1, dave_account.clone(), false, 1));
		assert_ok!(Assets::mint(
			RuntimeOrigin::signed(dave_account.clone()),
			0,
			bob_account.clone(),
			bob_asset_0_balance
		));
		assert_ok!(Assets::mint(
			RuntimeOrigin::signed(dave_account.clone()),
			1,
			charlie_account.clone(),
			charlie_asset_1_balance
		));

		// Alice, Bob and Charlie each start with 1000 * ED native currency.
		// Bob starts with 1000 of asset 0.
		// Charlie starts with 1000 of asset 1.
		// Random scenario demonstrating batching of calls that depend on one another:
		// - Alice buys 100 asset 0 for 100 native from Bob
		// - Alice buys 50 asset 1 for 75 asset 0 from Charlie
		// - Charlie buys 75 native for 75 asset 0 from Bob
		let genesis_hash = System::block_hash(0);
		let mut meta_txs: Vec<MetaTxFor<Runtime>> = vec![];

		// Give Bob 100 native from Alice.
		let call = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
			dest: bob_account.clone(),
			value: 100,
		});
		let meta_tx =
			MetaTxFor::<Runtime>::new(alice_account.clone(), call.clone(), 0, genesis_hash, 0);
		meta_txs.push(meta_tx);
		// Give Alice 100 asset 0 from Bob.
		let call = RuntimeCall::Assets(pallet_assets::Call::transfer {
			id: 0,
			target: alice_account.clone(),
			amount: 100,
		});
		let meta_tx =
			MetaTxFor::<Runtime>::new(bob_account.clone(), call.clone(), 0, genesis_hash, 0);
		meta_txs.push(meta_tx);
		// Give Charlie 75 asset 0 from Alice.
		let call = RuntimeCall::Assets(pallet_assets::Call::transfer {
			id: 0,
			target: charlie_account.clone(),
			amount: 75,
		});
		let meta_tx =
			MetaTxFor::<Runtime>::new(alice_account.clone(), call.clone(), 0, genesis_hash, 0);
		meta_txs.push(meta_tx);
		// Give Alice 50 asset 1 from Charlie.
		let call = RuntimeCall::Assets(pallet_assets::Call::transfer {
			id: 1,
			target: alice_account.clone(),
			amount: 50,
		});
		let meta_tx =
			MetaTxFor::<Runtime>::new(charlie_account.clone(), call.clone(), 0, genesis_hash, 0);
		meta_txs.push(meta_tx);
		// Give Charlie 75 native from Bob.
		let call = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
			dest: charlie_account.clone(),
			value: 75,
		});
		let meta_tx =
			MetaTxFor::<Runtime>::new(bob_account.clone(), call.clone(), 0, genesis_hash, 0);
		meta_txs.push(meta_tx);
		// Give Bob 75 asset 0 from Charlie.
		let call = RuntimeCall::Assets(pallet_assets::Call::transfer {
			id: 0,
			target: bob_account.clone(),
			amount: 75,
		});
		let meta_tx =
			MetaTxFor::<Runtime>::new(charlie_account.clone(), call.clone(), 0, genesis_hash, 0);
		meta_txs.push(meta_tx);

		let payload = crate::Pallet::<Runtime>::create_multisigner_payload(&meta_txs[..]).unwrap();

		let alice_sig = MultiSignature::Sr25519(alice_keyring.sign(&payload));
		let bob_sig = MultiSignature::Sr25519(bob_keyring.sign(&payload));
		let charlie_sig = MultiSignature::Sr25519(charlie_keyring.sign(&payload));
		let mut sigs = vec![
			(alice_account.clone(), alice_sig),
			(bob_account.clone(), bob_sig),
			(charlie_account.clone(), charlie_sig),
		];
		sigs.sort_by_key(|(account, _)| account.clone());
		let sigs: Vec<MultiSignature> = sigs.into_iter().map(|(_, sig)| sig).collect();

		// Encode and share with the world.
		let meta_txs_with_sigs_encoded = (meta_txs, sigs).encode();

		// Dave acts as meta transaction relayer.
		let (meta_txs, meta_tx_sigs): (Vec<MetaTxFor<Runtime>>, Vec<MultiSignature>) =
			Decode::decode(&mut &meta_txs_with_sigs_encoded[..]).unwrap();
		let proofs: Vec<ProofFor<Runtime>> =
			meta_tx_sigs.iter().cloned().map(|sig| Proof::Signed(sig)).collect();
		let call =
			RuntimeCall::MetaTx(Call::dispatch_multisigner { meta_txs: meta_txs.clone(), proofs });
		let tx_ext: Extension = (
			frame_system::CheckNonZeroSender::<Runtime>::new(),
			frame_system::CheckSpecVersion::<Runtime>::new(),
			frame_system::CheckTxVersion::<Runtime>::new(),
			frame_system::CheckGenesis::<Runtime>::new(),
			frame_system::CheckMortality::<Runtime>::from(sp_runtime::generic::Era::immortal()),
			frame_system::CheckNonce::<Runtime>::from(
				frame_system::Pallet::<Runtime>::account(&dave_account).nonce,
			),
			frame_system::CheckWeight::<Runtime>::new(),
			pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0),
		);

		let tx_sig = MultiSignature::Sr25519(
			(call.clone(), tx_ext.clone(), tx_ext.implicit().unwrap())
				.using_encoded(|e| dave_keyring.sign(&blake2_256(e))),
		);

		let uxt = UncheckedExtrinsic::new_signed(call, dave_account.clone(), tx_sig, tx_ext);

		// Check Extrinsic validity and apply it.

		let uxt_info = uxt.get_dispatch_info();
		let uxt_len = uxt.using_encoded(|e| e.len());

		let xt = <UncheckedExtrinsic as Checkable<IdentityLookup<AccountId>>>::check(
			uxt,
			&Default::default(),
		)
		.unwrap();

		let res = xt.apply::<Runtime>(&uxt_info, uxt_len).unwrap();

		// Asserting the results.

		assert!(res.is_ok());

		// Alice
		assert_eq!(alice_balance - 100, Balances::free_balance(&alice_account));
		assert_eq!(25, Assets::balance(0, &alice_account));
		assert_eq!(50, Assets::balance(1, &alice_account));

		// Bob
		assert_eq!(bob_balance + 25, Balances::free_balance(&bob_account));
		assert_eq!(bob_asset_0_balance - 25, Assets::balance(0, &bob_account));
		assert_eq!(0, Assets::balance(1, &bob_account));

		// Charlie
		assert_eq!(charlie_balance + 75, Balances::free_balance(&charlie_account));
		assert_eq!(0, Assets::balance(0, &charlie_account));
		assert_eq!(charlie_asset_1_balance - 50, Assets::balance(1, &charlie_account));

		// Alice, Bob and Charlie didn't pay, Dave paid the transaction fee.
		assert_eq!(dave_balance - tx_fee, Balances::free_balance(&dave_account));

		assert_eq!(System::account_nonce(&alice_account), 1);
		assert_eq!(System::account_nonce(&bob_account), 1);
		assert_eq!(System::account_nonce(&charlie_account), 1);
		assert_eq!(System::account_nonce(&dave_account), 1);
	});
}
