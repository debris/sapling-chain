use frame_support::{
    decl_event, decl_module, dispatch::{DispatchResult, DispatchError}, weights::SimpleDispatchInfo,
};
use frame_system::{self as system, ensure_signed};
use sp_std::vec::Vec;
use sapling::{SaplingSpendDescription, SaplingOutputDescription, zcash, accept_spend, accept_output, Point};

pub trait Trait: frame_system::Trait + pallet_timestamp::Trait + pallet_balances::Trait {
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
        fn validate_send(
            origin, 
            sighash: [u8; 32], 
            value_commitment: [u8; 32],
            anchor: [u8; 32],
            nullifier: [u8; 32],
            randomized_key: [u8; 32],
            // 192 elements
            zkproof: Vec<u8>,
            // 64 elements
            spend_auth_sig: Vec<u8>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let spend_vk = zcash::spend_vk();
            let mut point = Point::default();
            let spend_desc = SaplingSpendDescription {
                value_commitment,
                anchor,
                nullifier,
                randomized_key,
                zkproof: {
                    let mut data = [0u8; 192];
                    data.copy_from_slice(&zkproof);
                    data
                },
                spend_auth_sig: {
                    let mut data = [0u8; 64];
                    data.copy_from_slice(&spend_auth_sig);
                    data
                }
            };

            accept_spend(&spend_vk.into(), &sighash, &mut point, &spend_desc)
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
