#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;

use parity_scale_codec::Decode;
use parity_scale_codec::Encode;
use serde::Deserialize;
use sp_runtime::traits::BlockNumberProvider;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

pub const SNAPSHOT_STORAGE_KEY: &[u8] = b"pallet-ocw::claims";

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
        traits::BlockNumberProvider,
        transaction_validity::{
            InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
        },
        RuntimeDebug,
    };
    use sp_std::{collections::vec_deque::VecDeque, vec::Vec};

    use serde::{Deserialize, Deserializer};

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
        ice_address: Option<<T as frame_system::Config>::AccountId>,
        amount: u32,
        defi_user: bool,
        vesting_percentage: u32,
        claim_status: bool,
    }

    impl<T: Config> Default for SnapshotInfo<T> {
        fn default() -> Self {
            Self {
                ice_address: None,
                icon_address: sp_std::vec![],
                amount: 0,
                defi_user: false,
                vesting_percentage: 0,
                claim_status: false,
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

        pub fn ice_address(mut self, val: Option<T::AccountId>) -> Self {
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

        pub fn claim_status(mut self, val: bool) -> Self {
            self.claim_status = val;
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
        NewServerCounter(Option<T::AccountId>, u32),
        IconAddressAddedToMap(Vec<u8>),
        NewTransferMade(Option<T::AccountId>, Vec<u8>),
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
    #[pallet::getter(fn numbers)]
    pub type ServerCounter<T> = StorageValue<_, u32, ValueQuery>;

    /// IceAddress -> Pending claim request snapshot
    #[pallet::storage]
    #[pallet::getter(fn ice_snapshot_map)]
    pub(super) type IceSnapshotMap<T: Config> =
        StorageMap<_, Identity, Vec<u8>, SnapshotInfo<T>, OptionQuery>;

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
        NoClaimForUser,
        IconAddressAlreadyExists,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(block_number: T::BlockNumber) {
            log::info!("\n\n====================\nOffchain worker started\n=================\n");

            const TX_TYPES: u32 = 4;
            let modu = block_number
                .try_into()
                .map_or(TX_TYPES, |bn: usize| (bn as u32) % TX_TYPES);
            if modu == 0 {
                let mut temp_counter = <ServerCounter<T>>::get();
                for x in 1..101 {
                    log::info!("Loop index: {}", x);
                    temp_counter = temp_counter + 1;
                    let signer = Signer::<T, T::AuthorityId>::any_account();

                    if x % 100 == 0 {
                        // TODO: Error Handling
                        let result = signer.send_signed_transaction(|_account| {
                            Call::submit_counter_signed {
                                counter: temp_counter,
                            }
                        });
                    }

                    {
                        log::info!("x is: {}", &x);
                        log::info!("ServerCounter is: {:?}", <ServerCounter<T>>::get());
                    }
                    // TODO: Error Handling
                    let res = Self::__process_claim_request(&temp_counter);
                }
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

            // VERFICATION LOGIC GOES HERE

            // Fetch the snapshot entry from map
            let mut snapshotmap =
                Self::ice_snapshot_map(&icon_wallet).ok_or(<Error<T>>::NoClaimForUser)?;
            // Ensure the user has claim in our system
            ensure!(
                snapshotmap.claim_status == false,
                <Error<T>>::ClaimAlreadyMade
            );
            // Change the claim status for the user to true
            snapshotmap.claim_status = true;
            snapshotmap.ice_address = Some(who.clone());
            <IceSnapshotMap<T>>::insert(&icon_wallet, snapshotmap);

            let icon_to_snapshot = <IceSnapshotMap<T>>::get(icon_wallet.clone()).unwrap();

            // Transfer the amount to the sender
            Self::transfer_amount(
                icon_to_snapshot.ice_address.clone().unwrap(),
                icon_to_snapshot.amount,
            );

            log::info!("Claim Made for icon address: {:?} and with ice address: {:?}. Claim status changed to {:?}", icon_wallet.clone(), icon_to_snapshot.ice_address, icon_to_snapshot.claim_status );

            Self::deposit_event(Event::NewTransferMade(Some(who), icon_wallet));

            Ok(())
        }

        #[pallet::weight(0)]
        pub fn submit_counter_signed(origin: OriginFor<T>, counter: u32) -> DispatchResult {
            let who = ensure_signed(origin)?;
            log::info!("submit_counter_signed: ({}, {:?})", counter, who);
            <ServerCounter<T>>::put(counter);

            Self::deposit_event(Event::NewServerCounter(Some(who), counter));
            Ok(())
        }

        #[pallet::weight(0)]
        pub fn add_icon_address_to_map(
            origin: OriginFor<T>,
            _icon_address: Vec<u8>,
            _amount: u32,
            _defi_user: bool,
            _vesting_percentage: u32,
        ) -> DispatchResult {
            let icon_to_snapshot = <IceSnapshotMap<T>>::get(_icon_address.clone());

            // If this icx_address have already made an request
            ensure!(
                !icon_to_snapshot.is_some(),
                Error::<T>::IconAddressAlreadyExists
            );

            let new_snapshot = SnapshotInfo::<T> {
                ice_address: None,
                icon_address: _icon_address.clone(),
                defi_user: _defi_user.clone(),
                amount: _amount.clone(),
                vesting_percentage: _vesting_percentage.clone(),
                claim_status: false,
            };

            // insert generated snapshot
            <IceSnapshotMap<T>>::insert(_icon_address.clone(), new_snapshot);

            // emit success event
            Self::deposit_event(Event::IconAddressAddedToMap(
                (_icon_address.clone()).to_vec(),
            ));

            log::info!("Snapshot added to IceSnapshotMap {:?}", _icon_address);

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn __process_claim_request(counter: &u32) -> Result<(), Error<T>> {
            let signer = Signer::<T, T::AuthorityId>::any_account();

            let server_response =
                Self::fetch_claim_of(counter).ok_or(<Error<T>>::NoLocalAcctForSigning)?;
            let _server_response = server_response.clone();

            let result = signer.send_signed_transaction(|_account| {
                log::info!(
                    "Sending tx to add icon address to map, icon_address= {:?}",
                    _server_response.icon_address.clone()
                );
                Call::add_icon_address_to_map {
                    icon_address: _server_response.icon_address.clone(),
                    amount: _server_response.amount.clone(),
                    defi_user: _server_response.defi_user.clone(),
                    vesting_percentage: _server_response.vesting_percentage.clone(),
                }
            });

            log::info!("Transfer details from server: {:?}", server_response);

            Ok(())
        }

        fn fetch_claim_of(counter: &u32) -> Option<ServerResponse> {
            let request_url = "https://0.0.0.0:8000/test.html";

            match Self::fetch_from_remote(&request_url, counter) {
                Ok(response) => {
                    if let Ok(info) = serde_json::from_slice(response.as_slice()) {
                        return Some(info);
                    } else {
                        log::info!("Could not destruct http response to json struct..");
                        // response is not a valid json
                        return None;
                    }
                }
                Err(err) => {
                    // TODO: See the error of http request and retry if that will help
                    log::info!("fetch_from_remote returned with an error: {:?}", err);
                    return None;
                }
            }
        }

        fn fetch_from_remote(request_url: &str, counter: &u32) -> Result<Vec<u8>, Error<T>> {
            // @sudip: Change the value of icon_address in the sample response according to counter
            // so that it can return unique icon addresses for each counter
            return Ok(crate::generate_response(*counter as usize));

            let sample_response = r##"{
                "icon_address":"10001",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":10
            }"##;
            let sample_response_2 = r##"{
                "icon_address":"10002",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":20
            }"##;
            let sample_response_3 = r##"{
                "icon_address":"10003",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":30
            }"##;
            let sample_response_4 = r##"{
                "icon_address":"10004",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":30
            }"##;
            let sample_response_5 = r##"{
                "icon_address":"10005",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":30
            }"##;
            let sample_response_6 = r##"{
                "icon_address":"10006",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":30
            }"##;
            let sample_response_7 = r##"{
                "icon_address":"10007",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":30
            }"##;
            let sample_response_8 = r##"{
                "icon_address":"10008",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":30
            }"##;
            let sample_response_9 = r##"{
                "icon_address":"10009",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":30
            }"##;
            let sample_response_10 = r##"{
                "icon_address":"100010",
                "amount":24928,
                "defi_user":true,
                "vesting_percentage":30
            }"##;
            if counter % 10 == 1 {
                return Ok(sample_response.as_bytes().to_vec());
            } else if counter % 10 == 2 {
                return Ok(sample_response_2.as_bytes().to_vec());
            } else if counter % 10 == 3 {
                return Ok(sample_response_3.as_bytes().to_vec());
            } else if counter % 10 == 4 {
                return Ok(sample_response_4.as_bytes().to_vec());
            } else if counter % 10 == 5 {
                return Ok(sample_response_5.as_bytes().to_vec());
            } else if counter % 10 == 6 {
                return Ok(sample_response_6.as_bytes().to_vec());
            } else if counter % 10 == 7 {
                return Ok(sample_response_7.as_bytes().to_vec());
            } else if counter % 10 == 8 {
                return Ok(sample_response_8.as_bytes().to_vec());
            } else if counter % 10 == 9 {
                return Ok(sample_response_9.as_bytes().to_vec());
            } else if counter % 10 == 0 {
                return Ok(sample_response_10.as_bytes().to_vec());
            }

            log::info!("Sending request to: {}", request_url);

            let request = http::Request::get(request_url);
            let timeout =
                sp_io::offchain::timestamp().add(Duration::from_millis(FETCH_TIMEOUT_PERIOD));

            log::info!("Initializing pending variable...");
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

        fn transfer_amount(receiver: <T as frame_system::Config>::AccountId, amount: u32) {
            // TODO:
            // implement transfer logic
            log::info!(
                "Crediting account {:?} with amount of {} ",
                receiver,
                amount
            );
        }
    }

    impl<T: Config> BlockNumberProvider for Pallet<T> {
        type BlockNumber = T::BlockNumber;

        fn current_block_number() -> Self::BlockNumber {
            <frame_system::Pallet<T>>::block_number()
        }
    }
}

fn generate_response(counter: usize) -> sp_std::vec::Vec<u8> {
    let mut buffer = itoa::Buffer::new();
    let counter_bytes = buffer.format(counter);

    r##"{"icon_address": "this_address_refer_"##
        .as_bytes()
        .iter()
        .chain(counter_bytes.as_bytes())
        .chain(b"\",")
        .chain(r##""amount": 10982,"defi_user": true,"vesting_percentage": 14}"##.as_bytes())
        .cloned()
        .collect::<sp_std::vec::Vec<u8>>()
}

#[cfg(test)]
#[test]
fn test_generated_response() {
    for i in 0..5 {
        eprintln!("\n====================\n");
        eprintln!("{}", String::from_utf8(generate_response(i)).unwrap());
        eprintln!("\n====================\n");
    }

    for i in usize::MAX - 3..usize::MAX {
        eprintln!("\n====================\n");
        eprintln!("{}", String::from_utf8(generate_response(i)).unwrap());
        eprintln!("\n====================\n");
    }
}
