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

#[derive(Deserialize, RuntimeDebug)]
enum ServerResponseError {
    NoData,
    ServerError,
}

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

    #[derive(Encode, RuntimeDebug, Decode, Clone, scale_info::TypeInfo)]
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

        // this indicate that given icon address do not exists in server
        // so we neither do transfer nor will save this as failed claim
        NoDataInServer,
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
            log::info!(
                "Storage key: {:?} storred in block {:?}",
                storage_key,
                block_number
            );
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
            log::info!(
                "[GET] Storage key: {:?} storred in block {:?}",
                key,
                block_number
            );
            let db_reader = StorageValueRef::persistent(&key);

            // All failed requests in this offchain worker
            let mut failed_requests = sp_std::vec![];

            let rewrite_status =
                db_reader.mutate::<Vec<SnapshotInfo<T>>, (), _>(|claim_requests| {
                    match claim_requests {
                        Ok(Some(mut claim_requests)) => {
                            log::info!(
                                "For block {:?} there are {} claim requests to process",
                                block_number,
                                claim_requests.len()
                            );

                            log::info!(
                                "No. of claims we are processing is: {}",
                                claim_requests.len()
                            );
                            // Add some amount of previously failed requests to the processing queue
                            Self::add_failed_claims(&mut claim_requests);
                            log::info!(
                                "No, of claims to process after adding some failed claims is: {}",
                                claim_requests.len()
                            );

                            for claim in claim_requests.into_iter() {
                                let claim_status = Self::process_claim_requests(claim.clone());

                                if claim_status.is_ok() {
                                    log::info!(
                                        "Claim request for ice: {:?} passed..",
                                        claim.ice_address
                                    );
                                } else {
                                    log::info!(
                                        "Claim request for \nice_address: {:?}\nicon_address: {:?}",
                                        claim.ice_address,
                                        claim.icon_address
                                    );

                                    // add to failed queue
                                    failed_requests.push(claim);
                                }
                            }
                        }
                        Ok(None) => {
                            log::info!("Nothing is stored in claim request key.");
                        }
                        Err(err) => {
                            log::info!(
                                "db_reader.mutate error on claim requests. Error: {:?}",
                                err
                            );
                        }
                    }

                    // always clear this block storage at last
                    Ok(sp_std::vec![])
                });

            // save all the failed requests in seperate storage key
            Self::save_failed_requests(failed_requests);

            if rewrite_status.is_err() {
                panic!("Rewrite status panic");
            }

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

        #[pallet::weight(0)]
        pub fn transfer_fund(
            origin: OriginFor<T>,
            reciver: T::AccountId,
            amount: u128,
        ) -> DispatchResult {
            let who = ensure_signed(origin);

            // TODO: check if this sender can call the function

            log::info!(
                "Crediting account {:?} with amount {} unit",
                reciver,
                amount
            );

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn process_claim_requests(snapshot: SnapshotInfo<T>) -> Result<(), ()> {
            let server_response = Self::fetch_from_server(&snapshot);

            // if this icon address do not exists in server just return
            // pretrnding that the requests succeed
            if let Err(Error::<T>::NoDataInServer) = server_response {
                log::info!(
                    "Data for icon_address: {:?} do not exists in remote server",
                    snapshot.icon_address
                );

                // This much for this snapshot.
                // pretend we succed.
                return Ok(());
            }

            // TODO:
            // Exhaustive Error handeling

            // TODO:
            // transfer_balance

            Ok(())
        }

        fn fetch_from_server(snapshot: &SnapshotInfo<T>) -> Result<ServerResponse, Error<T>> {
            let request_url = parity_scale_codec::alloc::string::String::from_utf8(
                b"http://35.175.202.72:5000/claimDetails?address=0x"
                    .iter()
                    .chain(hex::encode(&snapshot.icon_address).as_bytes())
                    .cloned()
                    .collect(),
            )
            .map_err(|err| {
                log::info!("Error while encoding dynamic url. Error: {}", err);
                Error::DeserializeToStrError
            })?;

            log::info!("Sending request to {}", request_url);
            let request = http::Request::get(&request_url);
            let timeout =
                sp_io::offchain::timestamp().add(Duration::from_millis(FETCH_TIMEOUT_PERIOD));

            log::info!("Initilizing pending variable...");
            let pending = request
                .deadline(timeout) // Setting the timeout time
                .send() // Sending the request out by the host
                .map_err(|e| {
                    log::info!("Error while waiting for pending request{:?}", e);
                    Error::HttpFetchingError
                })?;

            log::info!("Initilizing response variable...");
            let response = pending
                .try_wait(timeout)
                .map_err(|_| Error::HttpFetchingError)?
                .map_err(|_| Error::HttpFetchingError)?;

            if response.code != 200 {
                log::info!("Unexpected HTTP request status code: {}", response.code);
                return Err(Error::HttpFetchingError);
            };

            let response_bytes = response.body().collect::<Vec<u8>>();
            let deserialize_to_response =
                serde_json::from_slice::<ServerResponse>(response_bytes.as_slice());

            // First try to deserialize body to ServerResponse which is the actual data we need,
            // if that fails, try to deserialize into ServerResponseError type which consist and
            // exhaustive list of all possible error returned by server
            // and furthemore if that also failes, giveup with DeserializeToObjError
            match deserialize_to_response {
                Ok(response) => Ok(response),
                Err(err) => {
                    log::info!("Deserialize into ServerResponse failed with error: {}", err);
                    let deserialixe_to_error = serde_json::from_slice::<crate::ServerResponseError>(
                        response_bytes.as_slice(),
                    );
                    match deserialixe_to_error {
                        Ok(error) => match error {
                            crate::ServerResponseError::NoData => Err(Error::<T>::NoDataInServer),
                            _ => Err(Error::<T>::HttpFetchingError),
                        },
                        Err(err) => {
                            log::info!(
                                "Cannot deserialize into error either. Error: {}. Failing...",
                                err
                            );
                            Err(Error::<T>::DeserializeToObjError)
                        }
                    }
                }
            }
        }

        fn get_master_block(current_block_number: &T::BlockNumber) -> T::BlockNumber {
            let is_ahead_by = *current_block_number % crate::BATCHING_BLOCK.into();

            current_block_number
                .checked_sub(&is_ahead_by)
                .unwrap_or_default()
        }

        fn save_failed_requests(mut failed_claims: Vec<SnapshotInfo<T>>) {
            if failed_claims.is_empty() {
                return;
            }

            let key = Self::get_failed_claims_storage_key();
            let db_writer = StorageValueRef::persistent(&key);

            let write_status = db_writer.mutate::<Vec<_>, (), _>(|prev_claims| match prev_claims {
                Ok(Some(mut prev_claims)) => {
                    prev_claims.append(&mut failed_claims);
                    log::info!("Appended in failed requests queue...");
                    Ok(prev_claims)
                }
                Ok(None) => Ok(failed_claims),
                Err(err) => {
                    log::info!("Failed claims getter failed with {:?}", err);
                    Err(())
                }
            });

            if write_status.is_err() {
                panic!("Failed to write in failed_claims....");
            }
        }

        fn add_failed_claims(claims: &mut Vec<SnapshotInfo<T>>) {
            // number of claims to move from failed queue to
            // recived claims list
            const FAILED_CLAIMS_TO_MOVE: usize = 3;

            let key = Self::get_failed_claims_storage_key();
            let writer = StorageValueRef::persistent(&key);

            let write_status = writer.mutate::<VecDeque<SnapshotInfo<T>>, (), _>(|failed_claims| {
                if let Ok(failed_claims) = failed_claims {
                    if let Some(mut failed_claims) = failed_claims {
                        for _ in 0..FAILED_CLAIMS_TO_MOVE {
                            if let Some(claim) = failed_claims.pop_front() {
                                claims.push(claim);
                            }
                        }
                        Ok(failed_claims)
                    } else {
                        log::info!("There is nothing in failed claims storage...");
                        Ok([].into())
                    }
                } else {
                    log::info!("Couldn't read failed requests storage..");
                    Err(())
                }
            });

            if write_status.is_ok() {
                log::info!("Couldn't add faled claims to processing vector...");
            } else {
                log::info!(
                    "Added {} failed claims to processing claims",
                    FAILED_CLAIMS_TO_MOVE
                );
            }
        }

        fn get_storage_key(current_block_number: &T::BlockNumber) -> Vec<u8> {
            let last_master_block = Self::get_master_block(&current_block_number);

            SNAPSHOT_STORAGE_KEY
                .iter()
                .chain(b"~from")
                .chain(last_master_block.encode().as_slice())
                .cloned()
                .collect()
        }

        fn get_failed_claims_storage_key() -> Vec<u8> {
            SNAPSHOT_STORAGE_KEY
                .iter()
                .chain(b"failed-claims")
                .cloned()
                .collect::<Vec<u8>>()
        }

        fn add_icon_address_to_map(signer: &T::AccountId, icon_addr: &[u8]) -> DispatchResult {
            let is_new_map = <IceSnapshotMap<T>>::contains_key(&signer);

            // If this icx_address have already made an request
            // return early
            // note that we do not panic here because use should be able to do claim
            // in multiple nodes ( if one node fails to process the request )
            //
            // However note that we should not override the values
            if !is_new_map {
                return Ok(());
            }

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
