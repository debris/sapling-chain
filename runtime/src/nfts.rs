use frame_support::{
    decl_event, decl_module, dispatch::{DispatchResult, DispatchError}, weights::SimpleDispatchInfo,
};
use frame_system::{self as system, ensure_signed};
use sp_std::vec::Vec;
use sapling::{self, SaplingOutputDescription, zcash, accept_spend, accept_output, Point};
use codec::{self, Input};

#[derive(Debug, Clone, PartialEq)]
pub struct SaplingSpendDescription {
    inner: sapling::SaplingSpendDescription,
}

impl From<sapling::SaplingSpendDescription> for SaplingSpendDescription {
    fn from(spend: sapling::SaplingSpendDescription) -> Self {
        Self {
            inner: spend,
        }
    }
}

impl codec::Decode for SaplingSpendDescription {
    fn decode<I: codec::Input>(value: &mut I) -> Result<Self, codec::Error> {
        let mut value_commitment = [0u8; 32];
        let mut anchor = [0u8; 32];
        let mut nullifier = [0u8; 32];
        let mut randomized_key = [0u8; 32];
        let mut zkproof = [0u8; 192];
        let mut spend_auth_sig = [0u8; 64];

        value.read(&mut value_commitment)?;
        value.read(&mut anchor)?;
        value.read(&mut nullifier)?;
        value.read(&mut randomized_key)?;
        value.read(&mut zkproof)?;
        value.read(&mut spend_auth_sig)?;

        let inner = sapling::SaplingSpendDescription {
            value_commitment,
            anchor,
            nullifier,
            randomized_key,
            zkproof,
            spend_auth_sig,
        };

        Ok(SaplingSpendDescription {
            inner
        })
    }
}

impl codec::Encode for SaplingSpendDescription {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        let inner = &self.inner;
        let mut output = [0u8; 4 * 32 + 192 + 64];
        output[..32].copy_from_slice(&inner.value_commitment);
        output[32..64].copy_from_slice(&inner.anchor);
        output[64..96].copy_from_slice(&inner.nullifier);
        output[96..128].copy_from_slice(&inner.randomized_key);
        output[128..320].copy_from_slice(&inner.zkproof);
        output[320..].copy_from_slice(&inner.spend_auth_sig);
        f(&output)
    }
}

pub trait Trait: frame_system::Trait {
    type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

decl_event!(
    pub enum Event<T> where <T as frame_system::Trait>::Hash {
        DepositAsset(Hash),
    }
);

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin  {
        fn deposit_event() = default;

        /// TODO:
        #[weight = SimpleDispatchInfo::FixedNormal(1_500_000)]
        fn validate_spend(
            origin, 
            sighash: [u8; 32], 
            spend_desc: SaplingSpendDescription,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let spend_vk = zcash::spend_vk();
            let mut point = Point::default();

            accept_spend(&spend_vk.into(), &sighash, &mut point, &spend_desc.inner)
                .map_err(|_| DispatchError::Other("verification failed"))
        }

        /// TODO:
        #[weight = SimpleDispatchInfo::FixedNormal(1_500_000)]
        fn validate_output(
            origin, 
            value_commitment: [u8; 32],
            note_commitment: [u8; 32],
            ephemeral_key: [u8; 32],
            // 580
            enc_cipher_text: Vec<u8>,
            // 80
            out_cipher_text: Vec<u8>,
            // 192 elements
            zkproof: Vec<u8>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let output_vk = zcash::output_vk();
            let mut point = Point::default();
            let output_desc = SaplingOutputDescription {
                value_commitment,
                note_commitment,
                ephemeral_key,
                enc_cipher_text: {
                    let mut data = [0u8; 580];
                    data.copy_from_slice(&zkproof);
                    data
                },
                out_cipher_text: {
                    let mut data = [0u8; 80];
                    data.copy_from_slice(&zkproof);
                    data
                },
                zkproof: {
                    let mut data = [0u8; 192];
                    data.copy_from_slice(&zkproof);
                    data
                },
            };

            accept_output(&output_vk.into(), &mut point, &output_desc)
                .map_err(|_| DispatchError::Other("verification failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
	use frame_support::{impl_outer_origin, parameter_types, weights::Weight};
	use sp_core::H256;
    use frame_system;
    use hex_literal::hex;
    use sp_runtime::{
        testing::Header,
        traits::{BadOrigin, BlakeTwo256, Hash, IdentityLookup},
        Perbill,
    };
    use sapling;

    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    type Nfts = super::Module<Test>;

    type System = frame_system::Module<Test>;

    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumBlockWeight: Weight = 1024;
        pub const MaximumBlockLength: u32 = 2 * 1024;
        pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
    }

    impl frame_system::Trait for Test {
        type AccountId = u64;
        type Call = ();
        type Lookup = IdentityLookup<Self::AccountId>;
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type Header = Header;
        type Event = ();
        type Origin = Origin;
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type MaximumBlockLength = MaximumBlockLength;
        type AvailableBlockRatio = AvailableBlockRatio;
        type Version = ();
        type ModuleToIndex = ();
        type AccountData = ();
        type OnNewAccount = ();
        type OnKilledAccount = ();
    }

    impl Trait for Test {
        type Event = ();
    }

    #[test]
    fn test_validate_spend() {
        let spend = sapling::SaplingSpendDescription {
            value_commitment: hex!("48b1c0668fce604361fbb1b89bbd76f8fee09b51a9dc0fdfcf6c6720cd596083"),
            anchor: hex!("d970234fcc0e9a70fdfed82d32fbb9ca92c9c5c3bad5daad9ac62b5bf4255817"),
            nullifier: hex!("ee5bc95a9af453bb9cc7e2c544aa29efa20011a65b624998369c849aa8f0bc83"),
            randomized_key: hex!("d60e7902a3cfe6eeaeb8d583a491de5982c5ded29e64cd8f8fac594a5bb4f283"),
            zkproof: hex!("8e6c30876e36a18d8d935238815c8d9205a4f1f523ff76b51f614bff1064d1c5fa0a27ec0c43c8a6c2714e7234d32e9a8934a3e9c0f74f1fdac2ddf6be3b13bc933b0478cae556a2d387cc23b05e8b0bd53d9e838ad2d2cb31daccefe256087511b044dfae665f0af0fa968edeea4cbb437a8099724159471adf7946eec434cccc1129f4d1e31d7f3f8be524226c65f28897d3604c14efb64bea6a889b2705617432927229dfa382e78c0ace31cc158fbf3ec1597242955e45af1ee5cfaffd78"),
            spend_auth_sig: hex!("9cc80dc53d6b18d42033ec2c327170e2811fe8ec00feadeb1033eb48ab24a6dce2480ad428be57c4619466fc3181ece69b914fed30566ff853250ef19ef73706"),
        };

        let sighash = hex!("839321aa5e46473277cc3828564f2a7b60d3fb1264320d6c436e74e7ffc75888");


        let _ = Nfts::validate_spend(
            Origin::signed(1),
            sighash,
            spend.into(),
        ).unwrap();
    }
}

