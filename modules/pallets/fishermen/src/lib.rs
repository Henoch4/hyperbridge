// Copyright (C) Polytope Labs Ltd.
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

//! Enables collators keep hyperbridge safe by vetoing fraudulent state
//! commitments and by blacklisting fraudulent rollup claims (opstack dispute
//! games / arbitrum assertions) before they reach the consensus verifier.
//!
//! The set of accounts allowed to act is the active collator set, sourced from
//! the runtime's `IsCollator` predicate. Any single collator can finalize a
//! veto or blacklist — there is no quorum yet (a 2/3 + bond quorum is planned
//! as a follow-up; see the calls below). Blacklist entries are reversible only
//! through the `AdminOrigin`-gated `unblacklist_*` extrinsics.
//!
//! NOTE: a full quorum (2/3 of collators + fisherman bond/slashing) is the
//! intended follow-up hardening for this pallet. The increment shipped here is
//! deliberately minimal and mergeable: fee-paying report calls (`Pays::Yes`),
//! an `AlreadyFinalized` duplicate-blacklist error, and `AdminOrigin`-gated
//! unblacklist extrinsics — without changing the single-collator finalization
//! path that existing tests cover.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;
pub use extension::PrioritizeVeto;
pub use pallet::*;
use polkadot_sdk::*;

mod extension;

use ismp::consensus::StateMachineId;
use primitive_types::{H160, H256};

/// Read-only view of the blacklists, consumed by the optimism / arbitrum
/// consensus verifier pallets to gate `verify_consensus`. Implemented for
/// [`Pallet`] by reading [`BlacklistedDisputeGames`] and
/// [`BlacklistedArbitrumClaims`].
pub trait FishermanBlacklist {
	/// True iff a (state_machine, opstack dispute-game proxy) pair has been blacklisted.
	fn is_dispute_game_blacklisted(state_machine_id: StateMachineId, proxy: H160) -> bool;
	/// True iff a (state_machine, arbitrum claim hash) pair has been blacklisted. The claim
	/// hash is the BoLD `assertionHash` for BoLD updates or
	/// `keccak256(state_hash || node_num.to_be_bytes())` for Orbit/AnyTrust updates.
	fn is_arbitrum_claim_blacklisted(state_machine_id: StateMachineId, claim: H256) -> bool;
}

/// No-op blacklist for runtimes that don't wire `pallet-fishermen`.
impl FishermanBlacklist for () {
	fn is_dispute_game_blacklisted(_: StateMachineId, _: H160) -> bool {
		false
	}
	fn is_arbitrum_claim_blacklisted(_: StateMachineId, _: H256) -> bool {
		false
	}
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::{dispatch::Pays, pallet_prelude::*, traits::{Contains, EnsureOrigin}};
	use frame_system::pallet_prelude::*;
	use ismp::{
		consensus::{StateCommitment, StateMachineHeight, StateMachineId},
		events::StateCommitmentVetoed,
		host::IsmpHost,
	};
	use primitive_types::{H160, H256};

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	/// The config trait
	#[pallet::config]
	pub trait Config: polkadot_sdk::frame_system::Config + pallet_ismp::Config {
		/// The underlying [`IsmpHost`] implementation
		type IsmpHost: IsmpHost + Default;

		/// Predicate that returns true when an account is currently entitled to
		/// submit a veto or blacklist call. Runtimes wire this to the active
		/// collator set (e.g. session validators intersected with
		/// collator-manager controllers).
		type IsCollator: Contains<Self::AccountId>;

		/// Governance origin allowed to reverse a finalized blacklist entry via
		/// the `unblacklist_*` extrinsics (e.g. `EnsureRoot` or the chain's
		/// `AdminOrigin`). This is the only path that removes an entry — a
		/// collator that submitted it cannot retract it.
		type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;
	}

	/// Finalized opstack dispute-game blacklist. Keyed by `(state_machine_id,
	/// dispute_game_proxy)`; the value is the collator account that submitted the blacklist.
	/// Read by `pallet-ismp-optimism::verify_consensus` to refuse `OpFaultProofGames` proofs
	/// that reference a blacklisted proxy; the recorded fisherman is kept for auditability
	/// and reputation accounting downstream.
	#[pallet::storage]
	#[pallet::getter(fn blacklisted_dispute_games)]
	pub type BlacklistedDisputeGames<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		StateMachineId,
		Blake2_128Concat,
		H160,
		T::AccountId,
		OptionQuery,
	>;

	/// Finalized arbitrum claim blacklist. Keyed by `(state_machine_id, claim_hash)` where
	/// `claim_hash` is the BoLD `assertionHash` for BoLD updates or
	/// `keccak256(state_hash || node_num.to_be_bytes())` for Orbit/AnyTrust updates; the
	/// value is the collator account that submitted the blacklist. Read by
	/// `pallet-ismp-arbitrum::verify_consensus`; the recorded fisherman is kept for
	/// auditability and reputation accounting downstream.
	#[pallet::storage]
	#[pallet::getter(fn blacklisted_arbitrum_claims)]
	pub type BlacklistedArbitrumClaims<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		StateMachineId,
		Blake2_128Concat,
		H256,
		T::AccountId,
		OptionQuery,
	>;

	#[pallet::error]
	pub enum Error<T> {
		/// Caller is not in the active collator set.
		UnauthorizedAction,
		/// State commitment was not found.
		VetoFailed,
		/// The (state machine, proxy/claim) pair is already blacklisted.
		/// A second `blacklist_*` call for a finalized entry fails with this
		/// error instead of silently succeeding, so duplicate reports are
		/// visible on-chain. Removal goes through the `AdminOrigin`-gated
		/// `unblacklist_*` extrinsics.
		AlreadyFinalized,
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// The provided state commitment was vetoed at `height` by `fisherman`.
		StateCommitmentVetoed {
			height: StateMachineHeight,
			commitment: StateCommitment,
			fisherman: T::AccountId,
		},
		/// The given opstack dispute-game proxy has been blacklisted by `fisherman`.
		DisputeGameBlacklisted {
			state_machine_id: StateMachineId,
			proxy: H160,
			fisherman: T::AccountId,
		},
		/// The given arbitrum claim hash has been blacklisted by `fisherman`.
		ArbitrumClaimBlacklisted {
			state_machine_id: StateMachineId,
			claim: H256,
			fisherman: T::AccountId,
		},
		/// A previously blacklisted opstack dispute-game proxy has been removed
		/// from the blacklist by `AdminOrigin`.
		DisputeGameUnblacklisted { state_machine_id: StateMachineId, proxy: H160 },
		/// A previously blacklisted arbitrum claim hash has been removed from
		/// the blacklist by `AdminOrigin`.
		ArbitrumClaimUnblacklisted { state_machine_id: StateMachineId, claim: H256 },
	}

	#[pallet::call]
	impl<T: Config> Pallet<T>
	where
		T::AccountId: AsRef<[u8]>,
	{
		/// A collator has determined that some [`StateCommitment`] (which is ideally still in
		/// its challenge period) is in fact fraudulent and misrepresentative of the state
		/// changes at the provided height. They aren't required to provide any proofs for
		/// this — any single collator's call deletes the commitment.
		///
		/// Dispatches with `Pays::Yes`: the signer pays the transaction fee on top of
		/// passing the on-chain `IsCollator` check, so fee-less spam from a compromised
		/// key still costs funds. (Previously `Pays::No`; flipped as minimal
		/// DOS-hardening until the 2/3 + bond quorum follow-up lands.)
		#[pallet::call_index(0)]
		#[pallet::weight((<T as frame_system::Config>::DbWeight::get().reads_writes(1, 2), Pays::Yes))]
		pub fn veto_state_commitment(
			origin: OriginFor<T>,
			height: StateMachineHeight,
		) -> DispatchResult {
			let account = ensure_signed(origin)?;
			ensure!(T::IsCollator::contains(&account), Error::<T>::UnauthorizedAction);

			let ismp_host = <T as Config>::IsmpHost::default();
			let commitment =
				ismp_host.state_machine_commitment(height).map_err(|_| Error::<T>::VetoFailed)?;
			ismp_host.delete_state_commitment(height).map_err(|_| Error::<T>::VetoFailed)?;

			Self::deposit_event(Event::StateCommitmentVetoed {
				height,
				commitment,
				fisherman: account.clone(),
			});
			pallet_ismp::Pallet::<T>::deposit_event(
				ismp::events::Event::StateCommitmentVetoed(StateCommitmentVetoed {
					height,
					fisherman: account.as_ref().to_vec(),
				})
				.into(),
			);

			Ok(())
		}

		/// A collator has determined that the opstack dispute game at `proxy` (registered
		/// against the configured `DisputeGameFactory` for `state_machine_id`) is fraudulent
		/// — typically because the off-chain fisherman watcher verified the claimed L2 output
		/// root against a supermajority (2/3·N + 1) of L2 RPC endpoints and observed a
		/// mismatch (or a quorum of the L2 height being absent).
		///
		/// Any single collator finalizes the blacklist. The entry is permanent unless
		/// removed through the `AdminOrigin`-gated `unblacklist_dispute_game` extrinsic —
		/// the consensus verifier will refuse any future `OpFaultProofGames` consensus
		/// proof that references this proxy while the entry exists.
		///
		/// A duplicate report for an already-blacklisted pair fails with
		/// [`Error::AlreadyFinalized`].
		///
		/// Dispatches with `Pays::Yes`: the signer pays the transaction fee on top of
		/// passing the on-chain `IsCollator` check (minimal DOS-hardening until the
		/// 2/3 + bond quorum follow-up lands).
		#[pallet::call_index(1)]
		#[pallet::weight((<T as frame_system::Config>::DbWeight::get().reads_writes(1, 1), Pays::Yes))]
		pub fn blacklist_dispute_game(
			origin: OriginFor<T>,
			state_machine_id: StateMachineId,
			proxy: H160,
		) -> DispatchResult {
			let account = ensure_signed(origin)?;
			ensure!(T::IsCollator::contains(&account), Error::<T>::UnauthorizedAction);

			// A finalized entry stays attributed to its original fisherman; a second
			// report is a visible error rather than a silent no-op.
			ensure!(
				!BlacklistedDisputeGames::<T>::contains_key(state_machine_id, proxy),
				Error::<T>::AlreadyFinalized
			);

			BlacklistedDisputeGames::<T>::insert(state_machine_id, proxy, account.clone());
			Self::deposit_event(Event::DisputeGameBlacklisted {
				state_machine_id,
				proxy,
				fisherman: account,
			});
			Ok(())
		}

		/// A collator has determined that the arbitrum claim identified by `claim` (a BoLD
		/// `assertionHash` or, for Orbit/AnyTrust, a derived hash of `state_hash || node_num`)
		/// is fraudulent.
		///
		/// Any single collator finalizes the blacklist. The entry is permanent unless
		/// removed through the `AdminOrigin`-gated `unblacklist_arbitrum_claim` extrinsic —
		/// the consensus verifier will refuse any future `ArbitrumOrbit` or `ArbitrumBold`
		/// consensus proof that resolves to this claim hash while the entry exists.
		///
		/// A duplicate report for an already-blacklisted pair fails with
		/// [`Error::AlreadyFinalized`].
		///
		/// Dispatches with `Pays::Yes`: the signer pays the transaction fee on top of
		/// passing the on-chain `IsCollator` check (minimal DOS-hardening until the
		/// 2/3 + bond quorum follow-up lands).
		#[pallet::call_index(2)]
		#[pallet::weight((<T as frame_system::Config>::DbWeight::get().reads_writes(1, 1), Pays::Yes))]
		pub fn blacklist_arbitrum_claim(
			origin: OriginFor<T>,
			state_machine_id: StateMachineId,
			claim: H256,
		) -> DispatchResult {
			let account = ensure_signed(origin)?;
			ensure!(T::IsCollator::contains(&account), Error::<T>::UnauthorizedAction);

			ensure!(
				!BlacklistedArbitrumClaims::<T>::contains_key(state_machine_id, claim),
				Error::<T>::AlreadyFinalized
			);

			BlacklistedArbitrumClaims::<T>::insert(state_machine_id, claim, account.clone());
			Self::deposit_event(Event::ArbitrumClaimBlacklisted {
				state_machine_id,
				claim,
				fisherman: account,
			});
			Ok(())
		}

		/// Remove a finalized opstack dispute-game blacklist entry. The dispatch origin
		/// must be `T::AdminOrigin` (governance) — the collator that submitted the
		/// blacklist cannot retract it. Idempotent: removing a pair that is not
		/// blacklisted is a no-op (no event emitted).
		#[pallet::call_index(3)]
		#[pallet::weight((<T as frame_system::Config>::DbWeight::get().reads_writes(1, 1), Pays::Yes))]
		pub fn unblacklist_dispute_game(
			origin: OriginFor<T>,
			state_machine_id: StateMachineId,
			proxy: H160,
		) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;

			if BlacklistedDisputeGames::<T>::contains_key(state_machine_id, proxy) {
				BlacklistedDisputeGames::<T>::remove(state_machine_id, proxy);
				Self::deposit_event(Event::DisputeGameUnblacklisted {
					state_machine_id,
					proxy,
				});
			}
			Ok(())
		}

		/// Remove a finalized arbitrum claim blacklist entry. The dispatch origin must
		/// be `T::AdminOrigin` (governance). Idempotent: removing a pair that is not
		/// blacklisted is a no-op (no event emitted).
		#[pallet::call_index(4)]
		#[pallet::weight((<T as frame_system::Config>::DbWeight::get().reads_writes(1, 1), Pays::Yes))]
		pub fn unblacklist_arbitrum_claim(
			origin: OriginFor<T>,
			state_machine_id: StateMachineId,
			claim: H256,
		) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;

			if BlacklistedArbitrumClaims::<T>::contains_key(state_machine_id, claim) {
				BlacklistedArbitrumClaims::<T>::remove(state_machine_id, claim);
				Self::deposit_event(Event::ArbitrumClaimUnblacklisted {
					state_machine_id,
					claim,
				});
			}
			Ok(())
		}
	}
}

impl<T: Config> FishermanBlacklist for Pallet<T> {
	fn is_dispute_game_blacklisted(state_machine_id: StateMachineId, proxy: H160) -> bool {
		BlacklistedDisputeGames::<T>::contains_key(state_machine_id, proxy)
	}

	fn is_arbitrum_claim_blacklisted(state_machine_id: StateMachineId, claim: H256) -> bool {
		BlacklistedArbitrumClaims::<T>::contains_key(state_machine_id, claim)
	}
}
