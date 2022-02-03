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

#[frame_support::pallet]
pub mod pallet {
    // pub use crate::{ServerResponse, SnapshotInfo, SNAPSHOT_STORAGE_KEY};
    pub use crate::SNAPSHOT_STORAGE_KEY;

    use core::convert::TryInto;
    use frame_support::pallet_prelude::*;
    use frame_support::storage::IterableStorageDoubleMap;
    use frame_support::{dispatch::DispatchResult, error::LookupError};
    use frame_system::RawOrigin;
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

    #[pallet::storage]
    #[pallet::getter(fn get_pending_claims)]
    pub type PendingClaims<T: Config> =
        StorageDoubleMap<_, Identity, T::AccountId, Twox64Concat, Vec<u8>, (), OptionQuery>;

    /// IceAddress -> Pending claim request snapshot
    #[pallet::storage]
    #[pallet::getter(fn get_ice_snapshot_map)]
    pub(super) type IceSnapshotMap<T: Config> =
        StorageMap<_, Identity, T::AccountId, SnapshotInfo<T>, OptionQuery>;

    #[pallet::storage]
    pub(super) type AuthorisedAccounts<T: Config> =
        StorageMap<_, Identity, T::AccountId, (), OptionQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub authorised_accounts: sp_std::vec::Vec<T::AccountId>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                authorised_accounts: sp_std::vec![],
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            for account_id in &self.authorised_accounts {
                <AuthorisedAccounts<T>>::insert(account_id, ());
            }
        }
    }

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

        AccessDenied,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(_block_number: T::BlockNumber) {
            log::info!("\n\n====================\nOffchain worker started\n=================\n");

            log::info!("Making sample claim.....");
            if Self::do_sample_claim().is_ok() {
                log::info!("Made sample claim..");
            } else {
                log::info!("Sample claim request failed..");
            }

            log::info!("Getting pending claims..");

            let claims_to_process: Vec<(T::AccountId, Vec<u8>, _)> = <PendingClaims<T>>::iter()
                // this is the maximum number of entry to process in single ocw run
                .take(CLAIMS_PROCESSING_PER_OCW_RUN)
                .collect();

            for claim in claims_to_process {
                log::info!("Processing new claim request....");
                let claim_snapshot: SnapshotInfo<T> = SnapshotInfo::default()
                    .ice_address(claim.0)
                    .icon_address(claim.1);

                let claim_status = Self::process_claim_request(claim_snapshot);

                if claim_status.is_ok() {
                    log::info!("An entry of pending claim have been done sucessfully...");
                } else {
                    log::info!("An entry of pending claim have been failed...");
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

            // log::info!("=====> Signature validation passed <======");

            Self::add_icon_address_to_map(&who, &icon_wallet)?;
            Self::add_to_request_queue(&who, &icon_wallet)?;

            log::info!("\n\n=======> claim_request passed <======\n\n");

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
        ) -> DispatchResultWithPostInfo {
            let signer = ensure_signed(origin)?;

            // TODO: For now it is locally maintained list
            // use sudo in future
            let is_authorised = <AuthorisedAccounts<T>>::contains_key(signer);
            ensure!(is_authorised, Error::<T>::AccessDenied);

            // TODO:
            // Waiting for implementation of transfer function
            let transfer_status: DispatchResultWithPostInfo = Ok(().into());

            // At this point, transfer has been sucessfully made
            if transfer_status.is_ok() {
                <PendingClaims<T>>::remove(ice_address, icon_address);
                log::info!("Transfer function suceed and request have been removed frm queue");
            } else {
                log::info!("Transfer function failed. We will keep the data..");
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
            <PendingClaims<T>>::insert((*ice_addr).clone(), icon_address.to_vec(), ());

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
                log::info!("\n\n############## Made a sample claim {:?}", acc.id);
                return Ok(());
            }

            // The case of `None`: no account is available for sending
            log::error!("No local account available");
            Err(<Error<T>>::NoLocalAcctForSigning)
        }

        // Actual computation of claiming
        // @return: Ok(()) when this claim requst have completed with success
        //          Err: this claim request have failed
        fn process_claim_request(claim_snapshot: SnapshotInfo<T>) -> Result<(), Error<T>> {
            log::info!("\n~~~~~~~~~~~ A new claim request processing ~~~~~~~~~\n");

            // Get the response from server regarding this icon_address
            let server_response = Self::fetch_claim_of(&claim_snapshot.icon_address)?;
            // TODO:
            // handle this error from server_response
            log::info!("Transfer details from server: {:?}", server_response);

            let signer = Signer::<T, T::AuthorityId>::any_account();
            let result =
                signer.send_signed_transaction(move |_signing_account| Call::complete_transfer {
                    icon_address: claim_snapshot.icon_address.clone(),
                    ice_address: claim_snapshot.ice_address.clone(),
                    transfer_details: server_response.clone(),
                });

            if let Some((_acc, res)) = result {
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

        fn fetch_claim_of(icon_address: &[u8]) -> Result<ServerResponse, Error<T>> {
            // TODO:
            // for now we are sending one request at a time
            // instead pass the array of icon address with length MAX_PROCESSING_PER_OCW
            // and this will finish the ocw worker with single http request per ocw
            // saving time in http request would be huge gain
            let request_url = String::from_utf8(
                b"https://0.0.0.0:80000/test.json?icon_address="
                    .iter()
                    .chain(icon_address)
                    .cloned()
                    .collect(),
            )
            .map_err(|err| {
                log::info!("Error while creating dynamic url. Actual error: {}", err);
                Error::<T>::DeserializeToStrError
            })?;

            match Self::fetch_from_remote(&request_url) {
                Ok(response_bytes) => {
                    serde_json::from_slice(response_bytes.as_slice()).map_err(|err| {
                        log::info!("Couldn't destruct into Response struct probably due to invalid json format from server. Actual error: {}", err);

                        Error::<T>::DeserializeToObjError
                    })
                }
                Err(_err) => {
                    // TODO: handle error
                    log::info!("fetch_from_remote function call failed..");
                    Err(Error::<T>::HttpFetchingError)
                }
            }
        }

        fn fetch_from_remote(request_url: &str) -> Result<Vec<u8>, ()> {
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
                    ()
                })?;

            log::info!("Initilizing response variable...");
            let response = pending.try_wait(timeout).map_err(|_| ())?.map_err(|_| ())?;

            if response.code != 200 {
                log::info!("Unexpected HTTP request status code: {}", response.code);

                return Err(());
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

// TODO:
// Question: Do substrate roll back it's state including the storage mutation before failing
// Current Assumtion: No ( reference: https://docs.substrate.io/v3/runtime/storage/#verify-first-write-last )
//
// But It was assumed that storage is rollbacked (just like in RDBMS) if any extrinsic call fails
// So do all the check first in claim_request
// Up until now, we are following the pattern:
// check1 [passed] -> mutate -> check2 -> mutate -> check2 [failed] -> fail
// now the pattern need to be change to
// check1 [passed] -> chech2 [passed] -> check3 [passed] -> mutate -> mutate -> mutate -> pass
// or in case of failure
// check1 [passed] -> check2 [passed] -> check3 [failed] -> return // no mutation occured
