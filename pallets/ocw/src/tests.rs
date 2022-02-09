use crate::{mock::*, Error};
use frame_support::{assert_err, assert_noop, assert_ok};

#[test]
fn make_claim_request() {
    new_test_ext().execute_with(|| {
        assert_ok!(TemplateModule::claim_request(
            Origin::signed(1),
            "0xicon_wallet"
        ));
        assert_ok!(TemplateModule::claim_request(
            Origin::signed(2),
            "0xanother_icon_wallet"
        ));

        // check that these two claims are in storageMap
        let have_first_wallet = TemplateModule::get_ice_snapshot_map(&1).is_some();
        let have_second_wallet = TemplateModule::get_ice_snapsho_map(&2).is_none();
        assert!(have_first_wallet && have_second_wallet);

        // make sure these mappings do not exists
        let no_unethical_map = TemplateModule::get_ice_snapsho_map(&3).is_none();
        assert!(no_unethical_map);
    });
}

#[test]
fn make_double_claim() {
    new_test_ext().execute_with(|| {
        let first_call = TemplateModule::claim_request(Origin::Signed(1), "0xsome_wallet");
        let second_call = TemplateModule::claim_request(Origin::Signed(1), "0xsome_another_wallet");

        // make sure first unique call passes
        assert_ok!(first_call);

        // make sure second call with same origin failed
        assert_err!(second_call, Error::<Test>::ClaimAlreadyMade);
    });
}

#[test]
fn signature_verification_pssed() {
    new_test_ext().execute_with(||{
        let icon_signature = sp_core::bytes::from_hex("0x628af708622383d60e1d9d95763cf4be64d0bafa8daebb87847f14fde0db40013105586f0c937ddf0e8913251bf01cf8e0ed82e4f631b666453e15e50d69f3b900").unwrap();
        let signed_data = "icx_sendTransaction.data.{method.transfer.params.{wallet.da8db20713c087e12abae13f522693299b9de1b70ff0464caa5d392396a8f76c}}.dataType.call.from.hxdd9ecb7d3e441d25e8c4f03cd20a80c502f0c374.nid.0x1.nonce.0x1..timestamp.0x5d56f3231f818.to.cx8f87a4ce573a2e1377545feabac48a960e8092bb.version.0x3".to_string().as_bytes().to_vec();
        let icon_wallet = sp_core::bytes::from_hex("0xee1448f0867b90e6589289a4b9c06ac4516a75a9").unwrap();
		let origin_address = "da8db20713c087e12abae13f522693299b9de1b70ff0464caa5d392396a8f76c".as_bytes().to_vec();

		assert_ok!(
            TemplateModule::validate_signature(
				origin_address,
				icon_signature,
				icon_wallet,
				signed_data
		    )
        );
    });
}

#[test]
fn test_oninitialize_hook() {
    new_test_ext().execute_with(|| {});
}
