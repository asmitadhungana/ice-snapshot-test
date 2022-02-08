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
    pub use crate::SNAPSHOT_STORAGE_KEY;

    use core::convert::TryInto;
    use frame_support::{
        pallet_prelude::*,
        traits::{
            Currency,
            tokens::ExistenceRequirement, 
            ReservableCurrency, 
            Get,
        },
        storage::IterableStorageDoubleMap,
        PalletId,
        dispatch::DispatchResult, 
        error::LookupError,
    };
    use frame_system::{
        offchain::{
            AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
            SignedPayload, Signer, SigningTypes, SubmitTransaction,
        },
        pallet_prelude::*,
        RawOrigin,
    };
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Deserializer};
    use sp_core::{crypto::KeyTypeId, hexdisplay::AsBytesRef};
    use sp_runtime::{
        offchain::{
            http,
            storage::StorageValueRef,
            storage_lock::{BlockAndTime, StorageLock},
            Duration,
        },
        traits::{BlockNumberProvider, AccountIdConversion, Saturating, SaturatedConversion},
        RuntimeDebug,
    };
    use sp_std::{vec::Vec};

    const CLAIMS_PROCESSING_PER_OCW_RUN: usize = 100;
    pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"shot");
    const FETCH_TIMEOUT_PERIOD: u64 = 3000; // in milli-seconds
    // const LOCK_TIMEOUT_EXPIRATION: u64 = FETCH_TIMEOUT_PERIOD + 1000; // in milli-seconds
    // const LOCK_BLOCK_EXPIRATION: u32 = 3; // in block number

    type AccountIdOf<T> = <T as frame_system::Config>::AccountId;
    type BalanceOf<T> = <<T as Config>::Currency as Currency<AccountIdOf<T>>>::Balance;

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

    #[derive(Encode, Decode, Clone, RuntimeDebug, scale_info::TypeInfo)]
    #[scale_info(skip_type_params(T))]
    pub struct SnapshotInfo<T: Config> {
        icon_address: Vec<u8>,
        ice_address: <T as frame_system::Config>::AccountId,
        amount: BalanceOf<T>,
        defi_user: bool,
        vesting_percentage: u32,
        claim_status: bool,
    }

    impl<T: Config> Default for SnapshotInfo<T> {
        fn default() -> Self {
            Self {
                ice_address: <T as frame_system::Config>::AccountId::default(),
                icon_address: sp_std::vec![],
                amount: Self::u128_to_balance_saturated(0),
                defi_user: false,
                vesting_percentage: 0,
                claim_status: false,
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
        Copy
    )]
    pub struct ServerResponse {
        omm: u32,
        #[serde(rename = "balanced")]
        balance: u128,
        stake: u128,
        defi_user: bool,
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

        pub fn amount(mut self, val: BalanceOf<T>) -> Self {
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
        
        pub fn u128_to_balance_saturated(input: u128) -> BalanceOf<T> {
            input.saturated_into()
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
        PalletFundUpdated(T::AccountId, BalanceOf<T>, BalanceOf<T>),
        ReceiverTokenBalanceUpdated(BalanceOf<T>, BalanceOf<T>),
    }

    #[pallet::config]
    pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
        /// The overarching event type.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// The overarching dispatch call type.
        type Call: From<Call<Self>>;
        /// The identifier type for an offchain worker.
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
        /// The Currency handler for the ocw pallet
        type Currency: Currency<Self::AccountId> + ReservableCurrency<Self::AccountId>;
        // The ocw pallet id, used for deriving its soverign account ID.
        #[pallet::constant]
        type PalletId: Get<PalletId>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn get_pending_claims)]
    pub type PendingClaims<T: Config> = StorageMap<_, Identity, T::AccountId, (), OptionQuery>;

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
            // Create Ocw-Pallet account and fund it with minimum balance
			let pallet_account_id = <Pallet<T>>::pallet_account_id();
			let min = T::Currency::minimum_balance();
			if T::Currency::free_balance(&pallet_account_id) < min {
				let _ = T::Currency::make_free_balance_be(&pallet_account_id, min);
			}
            // Set authorized accounts
            for account_id in &self.authorised_accounts {
                <AuthorisedAccounts<T>>::insert(account_id, ());
            }
        }
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    #[derive(Eq, PartialEq)]
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
        // Error returned when user has already made a claim for airdrop tokens
        ClaimAlreadyMade,
        NoDataInServer,
        AccessDenied,
        // Error returned when user has no claim to airdrop tokens
        NoClaimForUser,
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

            let claims_to_process: Vec<(T::AccountId, Vec<u8>)> = <PendingClaims<T>>::iter()
                // While collecting also take corresponding icon address
                .filter_map(|(ice_address, _)| {
                    let snapshot_of_ice = Self::get_ice_snapshot_map(&ice_address)?;
                    Some((ice_address, snapshot_of_ice.icon_address))
                })
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

            let already_exists_in_map = <IceSnapshotMap<T>>::contains_key(&who);
            let already_exists_in_queue = <PendingClaims<T>>::contains_key(&who);

            // TODO:
            // remove these log messages in production
            {
                if already_exists_in_map {
                    log::info!("This entry already exists in ice->snapshot map");
                }
                if already_exists_in_queue {
                    log::info!("This entry already exists in queue");
                }
            }

            // Ensure that this entry neither exists in request queue nor ice->snapshot map
            ensure!(
                !already_exists_in_queue && !already_exists_in_map,
                Error::<T>::ClaimAlreadyMade
            );

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
            transfer_details: Option<ServerResponse>,
        ) -> DispatchResultWithPostInfo {
            let signer = ensure_signed(origin)?;

            // TODO: For now it is locally maintained list
            // use sudo in future
            let is_authorised = <AuthorisedAccounts<T>>::contains_key(signer.clone());
            ensure!(is_authorised, Error::<T>::AccessDenied);

            // === TEMP: JUST FOR TESTING === //
            let before_pallet_balance = Self::pallet_fund();
            let before_receiver_balance = T::Currency::free_balance(&signer)
                .saturating_sub(T::Currency::minimum_balance());
            // === TEMP: JUST FOR TESTING === //

            let transfer_status: DispatchResultWithPostInfo =
                if let Some(transfer_details) = transfer_details {
                    // Actual transfer logic
                    let transfer_res = T::Currency::transfer(&Self::pallet_account_id(), &ice_address, Self::u128_to_balance_saturated(transfer_details.balance.clone()), ExistenceRequirement::KeepAlive);
                    if let Err(e) = transfer_res {
                        log::error!("Transfer Amount Error {:?}", e);
                    }
                    Ok(().into())
                } else {
                    // if None is passed in server response then
                    // we just have to remove the entry
                    Ok(().into())
                };

            // Update snapshot map for the user
            let defi_user =  &transfer_details.unwrap().defi_user;
            Self::update_snapshot_map(&signer, &defi_user).unwrap();

            // At this point, transfer has been sucessfully made
            if transfer_status.is_ok() {
                <PendingClaims<T>>::remove(ice_address);
                log::info!("Transfer function suceed and request have been removed frm queue");
            } else {
                log::info!("Transfer function failed. We will keep the data..");
            }

            // === TEMP: JUST FOR TESTING === //
            let remaining_pallet_balance = Self::pallet_fund();
            let after_receiver_balance = T::Currency::free_balance(&signer)
                .saturating_sub(T::Currency::minimum_balance());
            Self::deposit_event(Event::PalletFundUpdated(Self::pallet_account_id(), before_pallet_balance, remaining_pallet_balance));
            Self::deposit_event(Event::ReceiverTokenBalanceUpdated(before_receiver_balance, after_receiver_balance));
            // === TEMP: JUST FOR TESTING === //

            transfer_status
        }

        #[pallet::weight(10_000)]
        pub fn deposit(
            origin: OriginFor<T>,
            #[pallet::compact] value: BalanceOf<T>
        ) -> DispatchResult {
            let funder = ensure_signed(origin)?;
            
            let previous_pallet_balance = Self::pallet_fund();
            let pallet_account = Self::pallet_account_id();
            T::Currency::transfer(&funder, &pallet_account, value, ExistenceRequirement::KeepAlive)?;

            let remaining_pallet_balance = Self::pallet_fund();
            Self::deposit_event(Event::PalletFundUpdated(pallet_account, previous_pallet_balance, remaining_pallet_balance));
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {

        // RETURNS THE PALLET'S ACCOUNT ID
        pub fn pallet_account_id() -> T::AccountId {
            T::PalletId::get().into_account()
        }

        // RETURNS THE TOKEN BALANCE OF THE PALLET ACCOUNT
        pub fn pallet_fund() -> BalanceOf<T> {
            T::Currency::free_balance(&Self::pallet_account_id())
                // Must never be less than 0 but better be safe.
                .saturating_sub(T::Currency::minimum_balance())
        }

        pub fn u128_to_balance_saturated(input: u128) -> BalanceOf<T> {
            input.saturated_into()
        }

        pub fn balance_to_u128_saturated(input: BalanceOf<T>) -> u128 {
            input.saturated_into::<u128>()
        }

        fn add_icon_address_to_map(signer: &T::AccountId, icon_addr: &[u8]) -> DispatchResult {
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
            // insert this request as fresh entry
            <PendingClaims<T>>::insert((*ice_addr).clone(), ());

            Ok(())
        }

        fn update_snapshot_map(signer: &T::AccountId, defi_user: &bool) ->  DispatchResult {
            let mut snapshotmap =
                Self::get_ice_snapshot_map(&signer).ok_or(<Error<T>>::NoClaimForUser)?;
            ensure!(
                snapshotmap.claim_status == false,
                <Error<T>>::ClaimAlreadyMade
            );
            snapshotmap.claim_status = true;
            snapshotmap.defi_user = defi_user.clone();

            <IceSnapshotMap<T>>::insert(&signer, snapshotmap);

            Ok(())
        }

        fn do_sample_claim() -> Result<(), Error<T>> {
            return Ok(());

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

            // fetch the details from server
            let fetch_res = Self::fetch_claim_of(&claim_snapshot.icon_address);
            let server_response = match fetch_res {
                // normally do the further processing
                Ok(response) => Some(response),

                // There is no corresponding data for this icon address in server
                // In this case, just delete the entry from mapping
                Err(err) if err == Error::<T>::NoDataInServer => None,

                // propagate the error
                Err(err) => return Err(err),
            };

            log::info!("Response from server: {:#?}", server_response);

            // prepare to send the transaction
            let signer = Signer::<T, T::AuthorityId>::any_account();
            let result =
                signer.send_signed_transaction(move |_signing_account| Call::complete_transfer {
                    icon_address: claim_snapshot.icon_address.clone(),
                    ice_address: claim_snapshot.ice_address.clone(),
                    transfer_details: server_response.clone(),
                });

            // check if above disptachable call succeed ans display respective message
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
            let request_url = parity_scale_codec::alloc::string::String::from_utf8(
                b"http://35.175.202.72:5000/claimDetails?address=0x"
                    .iter()
                    .chain(hex::encode(icon_address).as_bytes())
                    .cloned()
                    .collect(),
            )
            .map_err(|err| {
                log::info!("Error while encoding dynamic url. Error: {}", err);
                Error::DeserializeToStrError
            })?;

            match Self::fetch_from_remote(&request_url) {
                Ok(response_bytes) => {
                    serde_json::from_slice(response_bytes.as_slice()).map_err(|err| {
                        log::info!("Couldn't destruct into Response struct probably due to invalid json format from server. Actual error: {}", err);

                        Error::DeserializeToObjError
                    })
                }
                Err(err) => {
                    log::info!("fetch_from_remote function call failed..");
                    Err(err)
                }
            }
        }

        // @return:
        // Ok(Vec<u8>) => server return some data with status 200
        // Err(true) => Fetching failed with some other errror,
        //              true specify that
        fn fetch_from_remote(request_url: &str) -> Result<Vec<u8>, Error<T>> {
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
                    Error::HttpFetchingError
                })?;

            log::info!("Initilizing response variable...");
            let response = pending
                .try_wait(timeout)
                .map_err(|_| Error::HttpFetchingError)?
                .map_err(|_| Error::HttpFetchingError)?;

            if response.code == 200 {
                Ok(response.body().collect())
            } else if response.code == 404 {
                log::info!("Server returned 404 status...");
                Err(Error::NoDataInServer)
            } else {
                log::info!("Unexpected HTTP request status code: {}", response.code);
                Err(Error::HttpFetchingError)
            }
        }
    }

    impl<T: Config> BlockNumberProvider for Pallet<T> {
        type BlockNumber = T::BlockNumber;

        fn current_block_number() -> Self::BlockNumber {
            <frame_system::Pallet<T>>::block_number()
        }
    }
}
