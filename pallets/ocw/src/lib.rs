#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;

use parity_scale_codec::Decode;
use parity_scale_codec::Encode;
use serde::Deserialize;
use sp_runtime::traits::BlockNumberProvider;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

// WARNING:
// Other pallets may also use key of same name. For now, substrate recommend
// to prefix with pallet-name. Otherwise two pallets will endup accssing
// storage by same key which will override the data of another pallet
pub const SNAPSHOT_STORAGE_KEY: &[u8] = b"pallet-ocw::claims";

pub const BATCHING_BLOCK: u8 = 5;

// Data structure to keep on offchain as well as onchain storage
// TODO:
// We might not need all this much of field?
// #[derive(Encode, Decode, Clone, Default, RuntimeDebug, scale_info::TypeInfo)]
// pub struct SnapshotInfo {
//     icon_address: Vec<u8>,
//     ice_address: Vec<u8>,
//     amount: u32,
//     defi_user: bool,
//     vesting_percentage: u32,
// }

// // Server response structure
// #[derive(Deserialize, Encode, Decode, Clone, Default, RuntimeDebug, scale_info::TypeInfo)]
// pub struct ServerResponse {
//     #[serde(deserialize_with = "de_string_to_bytes")]
//     icon_address: Vec<u8>,
//     amount: u32,
//     defi_user: bool,
//     vesting_percentage: u32,
//     // TODO:
//     // specify all fields
// }

// // implement builder pattern
// impl SnapshotInfo {
//     pub fn icon_address(mut self, val: Vec<u8>) -> Self {
//         self.icon_address = val;
//         self
//     }

//     pub fn ice_address(mut self, val: Vec<u8>) -> Self {
//         self.ice_address = val;
//         self
//     }

//     pub fn amount(mut self, val: u32) -> Self {
//         self.amount = val;
//         self
//     }

//     pub fn defi_user(mut self, val: bool) -> Self {
//         self.defi_user = val;
//         self
//     }

//     pub fn vesting_percentage(mut self, val: u32) -> Self {
//         self.vesting_percentage = val;
//         self
//     }
// }

#[frame_support::pallet]
pub mod pallet {
    // pub use crate::{ServerResponse, SnapshotInfo, SNAPSHOT_STORAGE_KEY};
    pub use crate::SNAPSHOT_STORAGE_KEY;

    use core::convert::TryInto;
    use frame_support::error::LookupError;
    use frame_support::pallet_prelude::*;
    use frame_system::{
        offchain::{
            AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
            SignedPayload, Signer, SigningTypes, SubmitTransaction,
        },
        pallet_prelude::*,
    };
    use parity_scale_codec::{Decode, Encode};
    use sp_core::{crypto::KeyTypeId, hexdisplay::AsBytesRef};
    use sp_runtime::{
        offchain::{
            http,
            storage::StorageValueRef,
            storage_lock::{BlockAndTime, StorageLock},
            Duration,
        },
        traits::{BlockNumberProvider, CheckedSub},
        transaction_validity::{
            InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
        },
        RuntimeDebug,
    };
    use sp_std::{collections::vec_deque::VecDeque, vec::Vec};

    use serde::{Deserialize, Deserializer};

    /// Defines application identifier for crypto keys of this module.
    ///
    /// Every module that deals with signatures needs to declare its unique identifier for
    /// its crypto keys.
    /// When an offchain worker is signing transactions it's going to request keys from type
    /// `KeyTypeId` via the keystore to sign the transaction.
    /// The keys can be inserted manually via RPC (see `author_insertKey`).
    pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"shot");
    const NUM_VEC_LEN: usize = 10;
    /// The type to sign and send transactions.
    const UNSIGNED_TXS_PRIORITY: u64 = 100;

    // const HTTP_REMOTE_REQUEST: &str = "http://0.0.0.0:8000/test.html";

    const FETCH_TIMEOUT_PERIOD: u64 = 3000; // in milli-seconds
    const LOCK_TIMEOUT_EXPIRATION: u64 = FETCH_TIMEOUT_PERIOD + 1000; // in milli-seconds
    const LOCK_BLOCK_EXPIRATION: u32 = 3; // in block number

    pub mod crypto {
        use crate::KEY_TYPE;
        use parity_scale_codec::alloc::string::String;
        use sp_core::sr25519::Signature as Sr25519Signature;
        use sp_runtime::{
            app_crypto::{app_crypto, sr25519},
            traits::Verify,
            MultiSignature, MultiSigner,
        };

        app_crypto!(sr25519, KEY_TYPE);

        pub struct TestAuthId;
        // implemented for runtime
        impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
            type RuntimeAppPublic = Public;
            type GenericSignature = sp_core::sr25519::Signature;
            type GenericPublic = sp_core::sr25519::Public;
        }

        // implemented for mock runtime in test
        impl
            frame_system::offchain::AppCrypto<
                <Sr25519Signature as Verify>::Signer,
                Sr25519Signature,
            > for TestAuthId
        {
            type RuntimeAppPublic = Public;
            type GenericSignature = sp_core::sr25519::Signature;
            type GenericPublic = sp_core::sr25519::Public;
        }
    }

    // type AccountOf<T> = <T as frame_system::Config>::AccountId;

    #[derive(Encode, Decode, Clone, RuntimeDebug, scale_info::TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct SnapshotInfo<T: Config> {
        icon_address: Vec<u8>,
        ice_address: <T as frame_system::Config>::AccountId,
        amount: u32,
        defi_user: bool,
        vesting_percentage: u32,
    }

    impl<T: Config> Default for SnapshotInfo<T> {
        fn default() -> Self {
            Self {
                ice_address: <T as frame_system::Config>::AccountId::default(),
                icon_address: sp_std::vec![],
                amount: 0,
                defi_user: false,
                vesting_percentage: 0,
            }
        }
    }

    // Server response structure
    #[derive(Deserialize, Encode, Decode, Clone, Default, RuntimeDebug, scale_info::TypeInfo)]
    pub struct ServerResponse {
        #[serde(deserialize_with = "de_string_to_bytes")]
        icon_address: Vec<u8>,
        amount: u32,
        defi_user: bool,
        vesting_percentage: u32,
        // TODO:
        // specify all fields
    }

    // implement builder pattern
    impl<T: Config> SnapshotInfo<T> {
        pub fn icon_address(mut self, val: Vec<u8>) -> Self {
            self.icon_address = val;
            self
        }

        pub fn ice_address(mut self, val: <T as frame_system::Config>::AccountId) -> Self {
            self.ice_address = val;
            self
        }

        pub fn amount(mut self, val: u32) -> Self {
            self.amount = val;
            self
        }

        pub fn defi_user(mut self, val: bool) -> Self {
            self.defi_user = val;
            self
        }

        pub fn vesting_percentage(mut self, val: u32) -> Self {
            self.vesting_percentage = val;
            self
        }
    }

    #[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
    pub struct Payload<Public> {
        number: u64,
        public: Public,
    }

    impl<T: SigningTypes> SignedPayload<T> for Payload<T::Public> {
        fn public(&self) -> T::Public {
            self.public.clone()
        }
    }

    #[derive(Debug, Deserialize, Encode, Decode, Default)]
    struct IndexingData(Vec<u8>, u64);

    pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(de)?;
        Ok(s.as_bytes().to_vec())
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        NewNumber(Option<T::AccountId>, u64),
        SnapshotInfoAdded(T::AccountId, Vec<u8>),
    }

    #[pallet::config]
    pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
        /// The overarching event type.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// The overarching dispatch call type.
        type Call: From<Call<Self>>;
        /// The identifier type for an offchain worker.
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    // The pallet's runtime storage items.
    // https://substrate.dev/docs/en/knowledgebase/runtime/storage
    #[pallet::storage]
    #[pallet::getter(fn numbers)]
    // Learn more about declaring storage items:
    // https://substrate.dev/docs/en/knowledgebase/runtime/storage#declaring-storage-items
    pub type Numbers<T> = StorageValue<_, VecDeque<u64>, ValueQuery>;

    /// IceAddress -> Pending claim request snapshot
    #[pallet::storage]
    #[pallet::getter(fn ice_snapshot_map)]
    pub(super) type IceSnapshotMap<T: Config> =
        StorageMap<_, Identity, T::AccountId, SnapshotInfo<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn get_ocw_middleware)]
    pub(super) type OcwMiddleware<T: Config> = StorageValue<_, Vec<SnapshotInfo<T>>, ValueQuery>;

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        // Error returned when not sure which ocw function to executed
        UnknownOffchainMux,

        // Error returned when making signed transactions in off-chain worker
        NoLocalAcctForSigning,
        OffchainSignedTxError,

        // Error returned when making unsigned transactions in off-chain worker
        OffchainUnsignedTxError,

        // Error returned when making unsigned transactions with signed payloads in off-chain worker
        OffchainUnsignedTxSignedPayloadError,

        // Error returned when fetching github info
        HttpFetchingError,
        DeserializeToObjError,
        DeserializeToStrError,

        OffchainStoreError,
        ClaimAlreadyMade,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(block_number: T::BlockNumber) {
            log::info!("On finalize called...");

            // get the all claims in this block and remove it afterward in single operation
            let this_block_data = <OcwMiddleware<T>>::take();
            if this_block_data.is_empty() {
                log::info!("This block have no claim requests..");
                return;
            }

            log::info!(
                "\n\n====>> This block has {} data <========\n",
                this_block_data.len()
            );

            let storage_key = Self::get_storage_key(&block_number);
            sp_io::offchain_index::set(&storage_key, &this_block_data.encode());
        }

        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            log::info!("On initialize called...");

            // always make sure middleware is clean
            <OcwMiddleware<T>>::kill();

            // TODO: return the weight consumed for this operation
            0
        }

        fn offchain_worker(block_number: T::BlockNumber) {
            if !Self::is_batched_master_block(&block_number) {
                log::info!(
                    "Offchain worker ignored for block number: {:?}",
                    block_number
                );
                return;
            }

            let key = Self::get_storage_key(&block_number);
            let db_reader = StorageValueRef::persistent(&key);

            let all_values = db_reader.get::<Vec<SnapshotInfo<T>>>();
            let all_values = if let Ok(Some(values)) = all_values {
                if values.is_empty() {
                    log::info!("\n##################### Empty storage..");
                    return;
                }
                values
            } else {
                log::info!("Cannot retrive value from offchain storage...");
                // TODO:
                return;
            };

            log::info!("\n\n====================\nOffchain worker started\n=================\n");

            log::info!(
                "For block {:?}. Storage have {} items",
                block_number,
                all_values.len()
            );

            log::info!("\n\n====================\nOffchain worker completed\n=================\n");
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(10_000)]
        pub fn claim_request(
            origin: OriginFor<T>,
            // icon_signature: Vec<u8>,
            icon_wallet: Vec<u8>,
            // tx_obj: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // let signer = hex::encode(who.encode());
            // let signer = signer.as_bytes();

            // Self::validate_signature(&signer, &icon_signature, &icon_wallet, &tx_obj)?;

            log::info!("\n=====> Signature validation passed <======\n");

            Self::add_icon_address_to_map(&who, &icon_wallet)?;
            Self::add_snapshot_to_offchain_db(&who, &icon_wallet)?;

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn get_storage_key(current_block_number: &T::BlockNumber) -> Vec<u8> {
            let last_master_block = {
                let is_ahead_by = *current_block_number % crate::BATCHING_BLOCK.into();

                current_block_number
                    .checked_sub(&is_ahead_by)
                    .unwrap_or_default()
            };

            SNAPSHOT_STORAGE_KEY
                .iter()
                .chain(b"~from")
                .chain(last_master_block.encode().as_slice())
                .cloned()
                .collect()
        }

        fn add_icon_address_to_map(signer: &T::AccountId, icon_addr: &[u8]) -> DispatchResult {
            let ice_to_snapshot = <IceSnapshotMap<T>>::get(&signer);

            // If this icx_address have already made an request
            ensure!(ice_to_snapshot.is_none(), Error::<T>::ClaimAlreadyMade);

            // create a new snapshot to be inserted
            let new_snapshot = SnapshotInfo::default().icon_address(icon_addr.to_vec());

            // insert generated snapshot
            <IceSnapshotMap<T>>::insert(&signer, new_snapshot);

            // emit success event
            Self::deposit_event(Event::SnapshotInfoAdded(
                (*signer).clone(),
                icon_addr.to_vec(),
            ));

            log::info!("Snapshot added to IceSnapshotMap {:?}", &signer);

            Ok(())
        }

        fn add_snapshot_to_offchain_db(
            ice_addr: &T::AccountId,
            icon_address: &[u8],
        ) -> DispatchResult {
            let to_insert = SnapshotInfo::default()
                .ice_address((*ice_addr).clone())
                .icon_address(icon_address.to_vec());

            <OcwMiddleware<T>>::append(to_insert);

            Ok(())
        }

        fn is_batched_master_block(block_number: &T::BlockNumber) -> bool {
            *block_number % (crate::BATCHING_BLOCK.into()) == 0_u8.into()
        }
    }

    impl<T: Config> BlockNumberProvider for Pallet<T> {
        type BlockNumber = T::BlockNumber;

        fn current_block_number() -> Self::BlockNumber {
            <frame_system::Pallet<T>>::block_number()
        }
    }
}

// Step 1: fetch from offchain db: fetch_from_offchain_db()
// Step 2: for each wallet, pull from external server: fetch_from_remote()
// Step 3: Transfer to fetched ice_address with fetched amount

// TODO: @asmee: Optimize offchain db for many claim entries: maybe keep different ids for each 100 claims
//       @sudip: Or maybe just keep everything inside single key id? One seeming downside is that offchain storage may possible become large if lots of claims are made within single node. Anyway as offchain db is maintained with key/value pair i.e accessing an element from db with key is always O(0). If above-mentioned optimization needed to be done, instead maybe just process 100 iteration in offchain worker loop?
// TODO: pop from the storage
