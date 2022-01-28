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
    use sp_core::crypto::KeyTypeId;
    use sp_runtime::{
        offchain::{
            http,
            storage::StorageValueRef,
            storage_lock::{BlockAndTime, StorageLock},
            Duration,
        },
        traits::BlockNumberProvider,
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
        fn offchain_worker(block_number: T::BlockNumber) {
            log::info!("\n\n====================\nOffchain worker started\n=================\n");

            // TODO:
            // Below check will ensure that further processing will be done
            // only once in every 2 trigger of offchain worker
            /*
            if block_number % 2 != 0 {
                return;
            }
            */

            // TODO: Following block is temporary just to put some data in offchain storage
            {
                let to_insert: SnapshotInfo<T> = SnapshotInfo::default();
                let db_writer = StorageValueRef::persistent(SNAPSHOT_STORAGE_KEY);
                let _ = db_writer.mutate::<VecDeque<SnapshotInfo<T>>, (), _>(move |storage| {
                    let mut previous_storage = if let Ok(Some(prev_storage)) = storage {
                        prev_storage
                    } else {
                        VecDeque::new()
                    };

                    previous_storage.push_back(to_insert.clone());

                    Ok(previous_storage)
                });
            }

            // Maximum number of request to run in this ocw
            const MAX_PROCESSING_PER_OCW: u8 = 100;

            // TODO:
            // If we are really about to split work between offchain worker,
            // mutex locking should be tested to avoid race, dead lock and unintended modification

            // Process first 100 snapshot info in storage
            'storage_loop: for _ in 0..MAX_PROCESSING_PER_OCW {
                let next_claim_request = match Self::get_next_from_db() {
                    Some(res) => res,
                    None => {
                        // Nothing is left in storage now
                        break 'storage_loop;
                    }
                };
                log::info!("Processing a new claim request from offchain worker....");

                // Actual processing of claim: Signed Transaction by Offchain worker
                // let claim_request = Self::process_claim_request(next_claim_request);

                // if claim_request.is_some() {
                //     log::info!("Request processing passed...");
                // } else {
                //     log::info!("Request processing failed...");
                // }

                // CHANGED:
                let res = Self::__process_claim_request(next_claim_request);

                if let Err(e) = res {
                    log::error!("Error: {:?}", e);
                }

                // TODO:
                // In both case we remove the snapshot
                // In future, only remove when succeed
                Self::remove_first_from_db();
                Self::offchain_signed_tx(block_number);
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

            log::info!("=====> Signature validation passed <======");

            Self::add_icon_address_to_map(&who, &icon_wallet)?;
            Self::add_snapshot_to_offchain_db(&who, &icon_wallet)?;

            Ok(())
        }

        #[pallet::weight(10000)]
        pub fn submit_number_signed(origin: OriginFor<T>, number: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            log::info!("submit_number_signed: ({}, {:?})", number, who);
            Self::append_or_replace_number(number);

            Self::deposit_event(Event::NewNumber(Some(who), number));
            Ok(())
        }

        // CHANGE: ADDED FUNCTION BELOW
        #[pallet::weight(0)]
        pub fn _transfer_amount(
            origin: OriginFor<T>, 
            receiver: T::AccountId, 
            amount: u64
        ) -> DispatchResultWithPostInfo{
            // TODO:
            // implement transfer logic
            log::info!(
                "Crediting account {:?} with amount of {} ",
                receiver,
                amount
            );
            Ok(().into())
        }
    }

    impl<T: Config> Pallet<T> {
        fn add_icon_address_to_map(signer: &T::AccountId, icon_addr: &[u8]) -> DispatchResult {
            let ice_to_snapshot = <IceSnapshotMap<T>>::get(&signer);

            // If this icx_address have already made an request
            ensure!(!ice_to_snapshot.is_some(), Error::<T>::ClaimAlreadyMade);

            // create a new snapshot to be inserted
            let new_snapshot = SnapshotInfo::default().icon_address(icon_addr.to_vec());

            // insert generated snapshot
            <IceSnapshotMap<T>>::insert(&signer, new_snapshot);

            // emit success event
            Self::deposit_event(Event::SnapshotInfoAdded(
                (*signer).clone(),
                icon_addr.to_vec(),
            ));

            Ok(())
        }

        fn add_snapshot_to_offchain_db(
            ice_addr: &T::AccountId,
            icon_address: &[u8],
        ) -> DispatchResult {
            let to_insert = SnapshotInfo::default()
                .ice_address((*ice_addr).clone())
                .icon_address(icon_address.to_vec());

            // StorageValueRef::local ( fork-aware db ) is not stable ( have issue )
            // in dependency tree of substrate we are using. So always ::persistent
            let db_writer = StorageValueRef::persistent(SNAPSHOT_STORAGE_KEY);

            // Storage type is VecDeque of SnapshotInfo.
            // newer request are added at end of the vecdeque so
            // while assigning the claims we should pop from front
            // i.e start logic from front to maintain a fair queue system
            // First-in-first-out
            // TODO:
            // Wrap the storage inside lock while writing ( from here ) and reading ( from any other pallets )
            // And set appropriate lock timeout
            let writer_status =
                db_writer.mutate::<VecDeque<SnapshotInfo<T>>, (), _>(move |storage| {
                    let mut previous_storage = if let Ok(Some(prev_storage)) = storage {
                        prev_storage
                    } else {
                        VecDeque::new()
                    };

                    previous_storage.push_back(to_insert);
                    Ok(previous_storage)
                });

            ensure!(writer_status.is_ok(), Error::<T>::OffchainStoreError);

            Ok(())
        }

        /// Append a new number to the tail of the list, removing an element from the head if reaching
        ///   the bounded length.
        fn append_or_replace_number(number: u64) {
            Numbers::<T>::mutate(|numbers| {
                if numbers.len() == NUM_VEC_LEN {
                    let _ = numbers.pop_front();
                }
                numbers.push_back(number);
                log::info!("Number vector: {:?}", numbers);
            });
        }

        fn offchain_signed_tx(block_number: T::BlockNumber) -> Result<(), Error<T>> {
            // We retrieve a signer and check if it is valid.
            //   Since this pallet only has one key in the keystore. We use `any_account()1 to
            //   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
            let signer = Signer::<T, T::AuthorityId>::any_account();

            // Translating the current block number to number and submit it on-chain
            let number: u64 = block_number.try_into().unwrap_or(0);

            // `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
            //   - `None`: no account is available for sending transaction
            //   - `Some((account, Ok(())))`: transaction is successfully sent
            //   - `Some((account, Err(())))`: error occured when sending the transaction
            let result = signer.send_signed_transaction(|_acct|
				// This is the on-chain function
				Call::submit_number_signed{ number });

            // Display error if the signed tx fails.
            if let Some((acc, res)) = result {
                if res.is_err() {
                    log::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
                    return Err(<Error<T>>::OffchainSignedTxError);
                }
                // Transaction is sent successfully
                log::info!("Transaction sent successfully by {:?}", acc.id);
                return Ok(());
            }

            // The case of `None`: no account is available for sending
            log::error!("No local account available");
            Err(<Error<T>>::NoLocalAcctForSigning)
        }

        // Actual computation of claiming
        // @return: Some(()) when this claim requst have completed with success
        //          None: this claim request have failed
        fn process_claim_request(claim_snapshot: SnapshotInfo<T>) -> Option<()> {
            // new_snapshot will have all the data required in SnapshotInfo structure
            // this includes
            let server_response = Self::fetch_claim_of(&claim_snapshot.icon_address)?;

            log::info!("Transfer details from server: {:?}", server_response);

            // TODO:
            // Transfer amount with amount=server_response.amount
            //                      reciver=claim_snapshot.icon_address or ice_address?
            //                      sender= ?? ( maybe root or sudo )?

            Self::transfer_amount(&claim_snapshot.icon_address, server_response.amount.into());

            Some(())
        }

        fn _process_claim_request(claim_snapshot: SnapshotInfo<T>) -> Result<(), &'static str> {
            let signer = Signer::<T, T::AuthorityId>::all_accounts();
            if !signer.can_sign() {
                return Err(
                    "No local accounts available. Consider adding one via `author_insertKey` RPC.",
                )?
            }

            // new_snapshot will have all the data required in SnapshotInfo structure
            // this includes
            let server_response = Self::fetch_claim_of(&claim_snapshot.icon_address).ok_or("Fetch claim of failed.")?;

            log::info!("Transfer details from server: {:?}", server_response);

            let result = signer.send_signed_transaction(|_account| {
                // MAYBE ERROR ???
                Call::_transfer_amount{ receiver: claim_snapshot.ice_address.clone(), amount: server_response.amount.into()}
            });

            Ok(())
        }


        fn __process_claim_request(claim_snapshot: SnapshotInfo<T>) -> Result<(), Error<T>> {
            let signer = Signer::<T, T::AuthorityId>::any_account();


            // new_snapshot will have all the data required in SnapshotInfo structure
            // this includes
            let server_response = Self::fetch_claim_of(&claim_snapshot.icon_address).ok_or(<Error<T>>::NoLocalAcctForSigning)?;

            log::info!("Transfer details from server: {:?}", server_response);

            let result = signer.send_signed_transaction(|_account| {
                // MAYBE ERROR ???
                Call::_transfer_amount{ receiver: claim_snapshot.ice_address.clone(), amount: server_response.amount.into() }
            });

            // Display error if the signed tx fails.
            if let Some((acc, res)) = result {
                if res.is_err() {
                    log::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
                    return Err(<Error<T>>::OffchainSignedTxError);
                }
                // Transaction is sent successfully
                log::info!("Transaction sent successfully by {:?}", acc.id);
                return Ok(());
            }

            // The case of `None`: no account is available for sending
            log::error!("No local account available");
            Err(<Error<T>>::NoLocalAcctForSigning)
        }

        // TODO:
        // Possibly use sudo instead of root
        fn transfer_amount(receiver: &[u8], amount: u64) {
            // TODO:
            // implement transfer logic
            log::info!(
                "Crediting account {:?} with amount of {} ",
                receiver,
                amount
            );
        }

        fn remove_first_from_db() {
            let remover = StorageValueRef::persistent(SNAPSHOT_STORAGE_KEY);
            let remove_status =
                remover.mutate::<VecDeque<SnapshotInfo<T>>, (), _>(move |storage| {
                    let mut previous_storage = if let Ok(Some(prev_storage)) = storage {
                        prev_storage
                    } else {
                        // At this point there will always be at least one data inside storage
                        // upon which this method was called.
                        // if control reach this point, it means that this storage have been mutated
                        // from somewhere else which is unwanted race condition. So we just panic here
                        unreachable!();
                    };

                    // Always remove from front as get_next_from_db always return from front
                    // remember this is vecdeque so complxity of pop_front() = pop_back() = O(0)
                    previous_storage.pop_front();

                    Ok(previous_storage)
                });

            if let Err(err) = remove_status {
                // TODO:
                // Some proper handeling like retry
                panic!("Couldn't remove first element forn claim offchain storage. Error: ",);
            }
        }

        fn fetch_claim_of(icon_address: &[u8]) -> Option<ServerResponse> {
            // TODO:
            // 1) Put actual server url and paramater
            // NOTE:
            // we pass both the ice and icon addres to again verify
            // that server have also same mapping

            /*
            // FIXME:
            // format! macro argument is not available in this environment
            // It may get little weird to construct dynamic url while sending to actual server
            // for now we just use a static hardcoded address
            let request_url = format!(
                "https://0.0.0.0:800/test.html?&icon_address={icon}",
                icon = String::from_utf8(icon_address.to_vec()).unwrap_or("NONE".to_string()),
            );
            */
            let request_url = "https://0.0.0.0:8000/test.html";

            match Self::fetch_from_remote(&request_url) {
                Ok(response) => {
                    if let Ok(info) = serde_json::from_slice(response.as_slice()) {
                        Some(info)
                    } else {
                        log::info!("Couldnot destruct http response to json struct..");
                        // response is not a valid json
                        None
                    }
                }
                Err(err) => {
                    // TODO: See the error of http resuest and retry if that will help
                    log::info!("fetch_from_remote returned with an error: {:?}", err);
                    None
                }
            }
        }

        fn get_next_from_db() -> Option<SnapshotInfo<T>> {
            let reader = StorageValueRef::persistent(SNAPSHOT_STORAGE_KEY);

            // We do not directly remove snapshot from here
            // There may be error ( do not necessairly have to be wrong claim )
            // like http error, offchain panic or so.
            // That's why we just return first snapshot and removing part is done later
            // inside process_claim_request
            if let Ok(Some(claims_list)) = reader.get::<VecDeque<SnapshotInfo<T>>>() {
                // TODO:
                // cloning this struct may be heavy process ( as it contains multiple vector )
                // TODO:
                // claims_list may also be empty so do length check first
                if let Some(value) = claims_list.front() {
                    return Some((*value).clone());
                } else {
                    None
                }
            } else {
                // Either there is no claims to handle
                // or maybe reading from offchain storage failed.
                None
            }
        }

        fn fetch_from_remote(request_url: &str) -> Result<Vec<u8>, Error<T>> {
            // TODO:
            // This function will currently always panic with tokio contect error.
            // Reason: The dependency on use in this project is always based on commit hash from github
            //      and not on any specific tag or version. This lead to use of two different tokio version
            //      i.e tokio 0.x and tokio 1.x. Major version change in tokio and intermixing them creates contect error
            // Possible Solution: Work on whole project to use well stabilized tag of both substrate & frontier
            //
            // For this reason we just return the sample response hardcoded in bytes
            let sample_response = r##"{
                "icon_address":"10001",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":10
            }"##;
            return Ok(sample_response.as_bytes().to_vec());

            log::info!("Sending request to: {}", request_url);

            let request = http::Request::get(request_url);
            let timeout =
                sp_io::offchain::timestamp().add(Duration::from_millis(FETCH_TIMEOUT_PERIOD));

            log::info!("Initilizing pending variable...");
            let pending = request
                .deadline(timeout) // Setting the timeout time
                .send() // Sending the request out by the host
                .map_err(|e| {
                    log::info!("Error while waiting for pending request{:?}", e);
                    <Error<T>>::HttpFetchingError
                })?;

            log::info!("Initilizing response variable...");
            let response = pending
                .try_wait(timeout)
                .map_err(|_| <Error<T>>::HttpFetchingError)?
                .map_err(|_| <Error<T>>::HttpFetchingError)?;

            if response.code != 200 {
                log::info!("Unexpected HTTP request status code: {}", response.code);

                return Err(<Error<T>>::HttpFetchingError);
            }

            Ok(response.body().collect())
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
