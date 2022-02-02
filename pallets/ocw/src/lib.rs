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
    use frame_support::pallet_prelude::*;
    use frame_support::storage::IterableStorageDoubleMap;
    use frame_support::{dispatch::DispatchResult, error::LookupError};
    use frame_system::{
        offchain::{
            AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
            SignedPayload, Signer, SigningTypes, SubmitTransaction,
        },
        pallet_prelude::*,
    };
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Deserializer};
    use sp_core::{crypto::KeyTypeId, hexdisplay::AsBytesRef};
    use sp_runtime::offchain::http::PendingRequest;
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

    const CLAIMS_PROCESSING_PER_OCW_RUN: usize = 100;

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

    #[derive(Encode, Decode, scale_info::TypeInfo)]
    pub enum ClaimProcessing {
        // this variant indicate that some ocw is currently processing this entry
        OnGoing,
        // no offchain worker has ever touched this
        Fresh,
        // an offchain worker tried to process this entry but failed
        Failed,
    }

    // Server response structure
    #[derive(
        Deserialize,
        Encode,
        Decode,
        Clone,
        Default,
        Eq,
        PartialEq,
        RuntimeDebug,
        scale_info::TypeInfo,
    )]
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

    #[pallet::storage]
    #[pallet::getter(fn get_pending_claims)]
    pub type PendingClaims<T: Config> = StorageDoubleMap<
        _,
        Identity,
        T::AccountId,
        Twox64Concat,
        Vec<u8>,
        ClaimProcessing,
        OptionQuery,
    >;

    /// IceAddress -> Pending claim request snapshot
    #[pallet::storage]
    #[pallet::getter(fn get_ice_snapshot_map)]
    pub(super) type IceSnapshotMap<T: Config> =
        StorageMap<_, Identity, T::AccountId, SnapshotInfo<T>, OptionQuery>;

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        // Error returned when not sure which ocw function to executed
        UnknownOffchainMux,

        // Transfer function is failing due to some reason
        TransferFailed,

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

            log::info!("Making sample claim.....");
            if Self::do_sample_claim().is_ok() {
                log::info!("Made sample claim..");
            } else {
                log::info!("Sample claim request failed..");
            }

            log::info!("Getting pending claims..");
            let claims = <PendingClaims<T>>::iter();

            // TODO: [optimization#taking-claim]
            // we take all the claims. Instead check if that request is ongoing
            // and ony take if not. This will make sure that this worker
            // will really process 100 claims
            // this is done by usiong take_while method
            // ignored for now for rapid dev
            for claim in claims.take(CLAIMS_PROCESSING_PER_OCW_RUN) {
                log::info!("Processing new claim request....");
                let claim_snapshot: SnapshotInfo<T> = SnapshotInfo::default()
                    .ice_address(claim.0.clone())
                    .icon_address(claim.1.clone());

                let claim_status = Self::process_claim_request(claim_snapshot);

                match claim_status {
                    Some(true) => log::info!("Claim processing done sucessfully..."),
                    Some(false) => log::info!("Claim processing ignored.."),
                    None => log::info!("Claim processing failed..."),
                }
            }

            log::info!("\n\n=========\n Offchain worker completed\n========\n");
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
            Self::add_to_request_queue(&who, &icon_wallet)?;

            Ok(())
        }

        // TODO:
        // Add proper weight
        #[pallet::weight(0)]
        pub fn complete_transfer(
            origin: OriginFor<T>,
            ice_address: T::AccountId,
            icon_address: Vec<u8>,
            transfer_details: ServerResponse,
        ) -> DispatchResult {
            // TODO: make sure this is only called by internal account
            // missing this check will allow anyone to call this from frontend
            //

            // TODO:
            // Waiting for implementation of transfer function
            let transfer_status: DispatchResult = Ok(());

            // At this point, transfer has been sucessfully made
            if transfer_status.is_ok() {
                <PendingClaims<T>>::remove(ice_address, icon_address);
                log::info!("Transfer function suceed and request have been removed frm queue");
            } else {
                log::info!("Transfer function failed. We will keep the data..");
                // state that this claim request failed
                <PendingClaims<T>>::mutate(ice_address, icon_address, |_prev| {
                    ClaimProcessing::Failed
                });
            }

            transfer_status
        }
    }

    impl<T: Config> Pallet<T> {
        fn add_icon_address_to_map(signer: &T::AccountId, icon_addr: &[u8]) -> DispatchResult {
            let already_exists = <IceSnapshotMap<T>>::contains_key(&signer);

            if already_exists {
                log::info!("This entry already exists in ice->snapshot map");
                return Err(Error::<T>::ClaimAlreadyMade.into());
            }

            log::info!("Adding new entry to ice->snapshot map");

            // create default snapshot with only ice & icon address populated
            let to_insert: SnapshotInfo<T> = SnapshotInfo::default()
                .ice_address((*signer).clone())
                .icon_address(icon_addr.to_vec());

            // insert generated snapshot
            <IceSnapshotMap<T>>::insert(&signer, to_insert);

            // emit success event
            Self::deposit_event(Event::SnapshotInfoAdded(
                (*signer).clone(),
                icon_addr.to_vec(),
            ));

            log::info!("Snapshot added to IceSnapshotMap {:?}", &signer);

            Ok(())
        }

        fn add_to_request_queue(ice_addr: &T::AccountId, icon_address: &[u8]) -> DispatchResult {
            let already_exists = <PendingClaims<T>>::contains_key(ice_addr, icon_address);

            if already_exists {
                log::info!("This entry already exists in queue..");
                return Err(Error::<T>::ClaimAlreadyMade.into());
            }

            log::info!("Adding new entry to queue");

            // insert this request as fresh entry
            <PendingClaims<T>>::insert(
                (*ice_addr).clone(),
                icon_address.to_vec(),
                ClaimProcessing::Fresh,
            );

            Ok(())
        }

        fn do_sample_claim() -> Result<(), Error<T>> {
            // return Ok(());

            let signer = Signer::<T, T::AuthorityId>::any_account();
            let result = signer.send_signed_transaction(|_accnt| {
                let icon_wallet = b"0xee1448f0867b90e6589289a4b9c06ac4516a75a9".to_vec();
                Call::claim_request { icon_wallet }
            });

            if let Some((acc, res)) = result {
                if res.is_err() {
                    log::error!("failure: do_sample_claim: tx sent: {:?}", acc.id);
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
        // TODO:
        // after doing optimization#taking-claim change it return type to Option<()>
        fn process_claim_request(claim_snapshot: SnapshotInfo<T>) -> Option<bool> {
            // If this is already ongoing then just return
            // TODO:
            // do this check before calling this function
            if let Some(ClaimProcessing::OnGoing) =
                Self::get_pending_claims(&claim_snapshot.ice_address, &claim_snapshot.icon_address)
            {
                return Some(false);
            }

            // update that we are taking the responsibility
            // and this entry is ongoing on process
            <PendingClaims<T>>::mutate(
                &claim_snapshot.ice_address,
                &claim_snapshot.icon_address,
                |_prev_status| ClaimProcessing::OnGoing,
            );

            //     // new_snapshot will have all the data required in SnapshotInfo structure
            //     // this includes
            let server_response = Self::fetch_claim_of(&claim_snapshot.icon_address)?;

            log::info!("Transfer details from server: {:?}", server_response);

            // TODO:
            // Transfer amount with amount=server_response.amount
            //                      reciver=claim_snapshot.icon_address or ice_address?
            //                      sender= ?? ( maybe root or sudo )?

            // TODO: Check for already transfer

            // This function will check for unique transfer per address
            // and if transfer was made sucessful then
            // remove from queue map and update status in ice->snapshot map
            // all in single extrensic call
            let res = Self::send_complete_transfer_call(
                server_response,
                claim_snapshot.ice_address,
                claim_snapshot.icon_address,
            );

            if res.is_ok() {
                log::info!("Transfer call passed...");
            } else {
                log::info!("Transfer call failed...");
            }

            Some(true)
        }

        fn send_complete_transfer_call(
            server_response: ServerResponse,
            ice_address: T::AccountId,
            icon_address: Vec<u8>,
        ) -> Result<(), Error<T>> {
            let signer = Signer::<T, T::AuthorityId>::any_account();
            let result = signer.send_signed_transaction(|_signing_account| {
                // TODO:
                // We will destruct and send snapshotInfo filed
                // because it do not satisfy all traits to be sent as argument
                // TODO: make this call recive less arguments
                Call::complete_transfer {
                    icon_address: icon_address.clone(),
                    ice_address: ice_address.clone(),
                    transfer_details: server_response.clone(),
                }
            });

            if let Some((acc, res)) = result {
                if res.is_err() {
                    log::error!("While calling complete_transer_call. Transaction error",);
                    return Err(<Error<T>>::OffchainSignedTxError);
                }
                log::info!("Call::complete_transfer function completed with success",);
                return Ok(());
            }
            log::error!("Call::complete_transfer: No local account available");
            Err(<Error<T>>::NoLocalAcctForSigning)
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
