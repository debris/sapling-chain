use sp_core::{Pair, Public, sr25519};
use node_runtime::{
	AuthorityDiscoveryConfig, BabeConfig, BalancesConfig, CouncilConfig, DemocracyConfig,
	GrandpaConfig, ImOnlineConfig, MultiAccount, MultiAccountConfig, SessionConfig, SessionKeys,
	StakerStatus, StakingConfig, SystemConfig, WASM_BINARY,
};
use node_runtime::constants::currency::*;
use sc_service;
use sp_finality_grandpa::{AuthorityId as GrandpaId};
use sp_consensus_babe::{AuthorityId as BabeId};
use pallet_im_online::sr25519::{AuthorityId as ImOnlineId};
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_runtime::{Perbill, traits::{Verify, IdentifyAccount}};

pub use node_primitives::{AccountId, Balance, Hash, Signature};
pub use node_runtime::GenesisConfig;

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::ChainSpec<GenesisConfig>;

/// The chain specification option.
#[derive(Clone, Debug)]
pub enum Alternative {
	/// Whatever the current runtime is, with just Alice as an auth.
	Development,
	/// Whatever the current runtime is, with simple Alice/Bob auths.
	LocalTestnet,
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate stash, controller and session key from seed
/// Note: this should be used only for dev testnets.
pub fn get_authority_keys_from_seed(seed: &str) -> (
    AccountId,
    AccountId,
    GrandpaId,
    BabeId,
    ImOnlineId,
    AuthorityDiscoveryId,
) {
    (
        get_account_id_from_seed::<sr25519::Public>(&format!("{}//stash", seed)),
		get_account_id_from_seed::<sr25519::Public>(seed),
        get_from_seed::<GrandpaId>(seed),
        get_from_seed::<BabeId>(seed),
        get_from_seed::<ImOnlineId>(seed),
        get_from_seed::<AuthorityDiscoveryId>(seed),
    )
}

/// Get a chain config from a spec setting.
impl Alternative {
	pub(crate) fn load(self) -> Result<ChainSpec, String> {
		Ok(match self {
			Alternative::Development => development_config(),
			Alternative::LocalTestnet => local_testnet_config(),
		})
	}

	pub(crate) fn from(s: &str) -> Option<Self> {
		match s {
			"dev" => Some(Alternative::Development),
			"local" => Some(Alternative::LocalTestnet),
			_ => None,
		}
	}
}

fn session_keys(
    grandpa: GrandpaId,
    babe: BabeId,
    im_online: ImOnlineId,
    authority_discovery: AuthorityDiscoveryId,
) -> SessionKeys {
	SessionKeys { grandpa, babe, im_online, authority_discovery }
}

/// Helper function to create GenesisConfig for testing
pub fn testnet_genesis(
	// StashId, ControllerId, GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId
	initial_authorities: Vec<(AccountId, AccountId, GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId)>,
    endowed_accounts: Option<Vec<AccountId>>,
) -> GenesisConfig {
    let mut endowed_accounts: Vec<AccountId> = endowed_accounts.unwrap_or_else(|| {
		vec![
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			get_account_id_from_seed::<sr25519::Public>("Bob"),
			get_account_id_from_seed::<sr25519::Public>("Charlie"),
			get_account_id_from_seed::<sr25519::Public>("Dave"),
			get_account_id_from_seed::<sr25519::Public>("Eve"),
			get_account_id_from_seed::<sr25519::Public>("Ferdie"),
			get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
			get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
			get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
			get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
			get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
			get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
		]
	});
	// add a balance for the multi account id 1 created further down, this will have address
	// 5DnGuePtDg4x7vCiUgjxrfFVVvMiA5aBDKLRbAp4SVohAMn8 on the default substrate chain
	endowed_accounts.push(MultiAccount::multi_account_id(1));
    let num_endowed_accounts = endowed_accounts.len();

    const INITIAL_SUPPLY: Balance = 300_000_000 * RAD; // 3% of total supply
    const STASH: Balance = 1_000_000 * RAD;
    let endowment: Balance = (INITIAL_SUPPLY - STASH * (initial_authorities.len() as Balance)) /
        (num_endowed_accounts as Balance);

    GenesisConfig {
        frame_system: Some(SystemConfig {
            code: WASM_BINARY.to_vec(),
            changes_trie_config: Default::default(),
        }),
        pallet_balances: Some(BalancesConfig {
            balances: endowed_accounts.iter().cloned()
                .map(|k| (k, endowment))
                .chain(initial_authorities.iter().map(|x| (x.0.clone(), STASH)))
                .collect(),
        }),
        pallet_session: Some(SessionConfig {
			keys: initial_authorities.iter().map(|x| {
				(x.0.clone(), x.0.clone(), session_keys(x.2.clone(), x.3.clone(), x.4.clone(), x.5.clone()))
			}).collect::<Vec<_>>(),
		}),
		pallet_staking: Some(StakingConfig {
            // The current era index.
			current_era: 0,
            // The ideal number of staking participants.
			validator_count: initial_authorities.len() as u32 * 2,
			minimum_validator_count: initial_authorities.len() as u32,
			stakers: initial_authorities.iter().map(|x| {
				(x.0.clone(), x.1.clone(), STASH, StakerStatus::Validator)
			}).collect(),
            // Any validators that may never be slashed or forcibly kicked. It's a Vec since they're
            // easy to initialize and the performance hit is minimal (we expect no more than four
            // invulnerables) and restricted to testnets.
			invulnerables: initial_authorities.iter().map(|x| x.0.clone()).collect(),
            // The percentage of the slash that is distributed to reporters.
		    // The rest of the slashed value is handled by the `Slash`.
			slash_reward_fraction: Perbill::from_percent(10),
            // True if the next session change will be a new era regardless of index.
            // force_era: NotForcing
			.. Default::default()
        }),
        pallet_democracy: Some(DemocracyConfig::default()),
		pallet_collective_Instance1: Some(CouncilConfig {
			members: endowed_accounts.iter()
						.take((num_endowed_accounts + 1) / 2)
						.cloned()
						.collect(),
			phantom: Default::default(),
		}),
        pallet_babe: Some(BabeConfig {
            authorities: vec![],
        }),
        pallet_im_online: Some(ImOnlineConfig {
			keys: vec![],
        }),
        pallet_authority_discovery: Some(AuthorityDiscoveryConfig {
			keys: vec![],
		}),
        pallet_grandpa: Some(GrandpaConfig {
            authorities: vec![],
		}),
		substrate_pallet_multi_account: Some(MultiAccountConfig{
			multi_accounts: vec![
				// Add the first 3 accounts to a 2-of-3 multi account
				(endowed_accounts[0].clone(), 2, vec![endowed_accounts[1].clone(), endowed_accounts[2].clone()]),
			],
		}),
    }
}

fn get_default_properties(token: &str) -> sc_service::Properties {
    let data = format!("\
		{{
			\"tokenDecimals\": 18,\
			\"tokenSymbol\": \"{}\"\
		}}", token);
    serde_json::from_str(&data).unwrap()
}

fn development_config_genesis() -> GenesisConfig {
	testnet_genesis(
		vec![
			get_authority_keys_from_seed("Alice"),
		],
		None,
	)
}

/// Development config (single validator Alice)
pub fn development_config() -> ChainSpec {
	ChainSpec::from_genesis(
		"Development",
		"dev",
		development_config_genesis,
		vec![],
		None,
		None,
		Some(get_default_properties("DRAD")),
		Default::default(),
	)
}

fn local_testnet_genesis() -> GenesisConfig {
	testnet_genesis(
		vec![
			get_authority_keys_from_seed("Alice"),
			get_authority_keys_from_seed("Bob"),
		],
		None,
	)
}

/// Local testnet config (multivalidator Alice + Bob)
pub fn local_testnet_config() -> ChainSpec {
	ChainSpec::from_genesis(
		"Local Testnet",
		"local_testnet",
		local_testnet_genesis,
		vec![],
		None,
		None,
		Some(get_default_properties("DRAD")),
		Default::default(),
	)
}

pub fn load_spec(id: &str) -> Result<Option<ChainSpec>, String> {
	Ok(match Alternative::from(id) {
		Some(spec) => Some(spec.load()?),
		None => None,
	})
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use crate::service::{new_full, new_light};
	use sc_service_test;
	use sp_runtime::{ModuleId, BuildStorage, traits::AccountIdConversion};
	use sp_core::crypto::{Ss58Codec, Ss58AddressFormat::CentrifugeAccountDirect};


	fn local_testnet_genesis_instant_single() -> GenesisConfig {
		testnet_genesis(
			vec![
				get_authority_keys_from_seed("Alice"),
			],
			None,
		)
	}

	/// Local testnet config (single validator - Alice)
	pub fn integration_test_config_with_single_authority() -> ChainSpec {
		ChainSpec::from_genesis(
			"Integration Test",
			"test",
			local_testnet_genesis_instant_single,
			vec![],
			None,
			None,
			None,
			Default::default(),
		)
	}

	/// Local testnet config (multivalidator Alice + Bob)
	pub fn integration_test_config_with_two_authorities() -> ChainSpec {
		ChainSpec::from_genesis(
			"Integration Test",
			"test",
			local_testnet_genesis,
			vec![],
			None,
			None,
			None,
			Default::default(),
		)
	}

	#[test]
	#[ignore]
	fn test_connectivity() {
		sc_service_test::connectivity(
			integration_test_config_with_two_authorities(),
			|config| new_full(config),
			|config| new_light(config),
		);
	}

	#[test]
	fn test_centrifuge_multi_account_ids() {
		assert_eq!(MultiAccount::multi_account_id(1).to_ss58check_with_version(CentrifugeAccountDirect),
			"4d4KMh9TuvpbBZmw3VTpbFewd1Vwpyo45g1du4xFfNEmUKQV");
		assert_eq!(MultiAccount::multi_account_id(2).to_ss58check_with_version(CentrifugeAccountDirect),
			"4ghzKGVmwh7wKFaWVF3d4QTbg21AbTo4mMPM5YUkkQasth4e");
		assert_eq!(MultiAccount::multi_account_id(3).to_ss58check_with_version(CentrifugeAccountDirect),
			"4fM9N5BuADmbYBn4SPNnSVhfD9TVoBc83BC3ZJWei5FmAunc");
		assert_eq!(MultiAccount::multi_account_id(4).to_ss58check_with_version(CentrifugeAccountDirect),
			"4eHarY1f35y2wtbW3XKLbbnJHeztAjNsxcYEoMnjfQbKXyq3");
		assert_eq!(MultiAccount::multi_account_id(5).to_ss58check_with_version(CentrifugeAccountDirect),
			"4dTzs4ktTARToFk6k12Diu8ZHeP9bPCTfh1erAGhd3THtqCZ");
	}

	#[test]
	fn test_centrifuge_bridge_account_id() {
		let account_id: AccountId = ModuleId(*b"cb/bridg").into_account();
		assert_eq!(account_id.to_ss58check_with_version(CentrifugeAccountDirect),
			"4dpEcgqFor2TJw9uWSjx2JpjkNmTic2UjJAK1j9fRtcTUoRu");
	}

	#[test]
	fn test_create_development_chain_spec() {
		development_config().build_storage().unwrap();
	}

	#[test]
	fn test_create_local_testnet_chain_spec() {
		local_testnet_config().build_storage().unwrap();
	}
}
