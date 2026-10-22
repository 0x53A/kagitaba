use kagitaba_core::wallet::Wallet;
use kagitaba_cxf::{Document, PayloadKind};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};

fn fixture() -> Document {
    Document::from_json(&serde_json::to_vec(&json!({
        "version":{"major":1,"minor":2},"exporterRpId":"example.test","exporterDisplayName":"Synthetic","timestamp":0,"vendorHeader":true,
        "accounts":[{"id":"YQ","username":"Synthetic","email":"test@example.test","vendorAccount":7,
            "items":[{"id":"aQ","title":"Filed","credentials":[]},{"id":"ag","title":"Unfiled","credentials":[]}],
            "collections":[{"id":"Yw","title":"Original root","items":[{"item":"aQ"}],"unknown":{"kept":true},
                "subCollections":[{"id":"ZA","title":"Nested","items":[{"item":"ag"},{"item":"bWlzc2luZw"}]}]}]}]
    })).unwrap()).unwrap()
}

#[test]
fn enclosing_collection_links_all_items_and_preserves_nested_trees_and_provenance() {
    let document = fixture();
    let original = document.to_json().unwrap();
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let mut plan = document.plan_import(&Wallet::default(), &mut rng).unwrap();
    let before: Vec<_> = plan
        .entries()
        .iter()
        .map(|p| (p.entry_id(), p.kind(), p.to_json().unwrap()))
        .collect();
    let old_root = plan
        .entries()
        .iter()
        .find(|p| p.kind() == PayloadKind::Collection)
        .unwrap();
    let old_entity = old_root.entity().clone();
    let mut old_envelope: Value = serde_json::from_slice(&old_root.to_json().unwrap()).unwrap();
    old_envelope.as_object_mut().unwrap().remove("entity");
    let root = plan.wrap_collection("Synthetic import", &mut rng).unwrap();
    assert!(before.iter().all(|(id, _, _)| *id != root));
    assert_eq!(plan.report().items, 2);
    assert_eq!(plan.report().root_collections, 1);
    assert_eq!(plan.report().unresolved_links, 1);
    let wrapper = plan
        .entries()
        .iter()
        .find(|p| p.entry_id() == root)
        .unwrap();
    assert_eq!(wrapper.entity()["title"], "Synthetic import");
    assert_eq!(wrapper.entity()["subCollections"][0], old_entity);
    assert_eq!(
        wrapper.source().unwrap()["collections"][0]["envelope"],
        old_envelope
    );
    for (id, kind, bytes) in before {
        if kind == PayloadKind::Item {
            assert_eq!(
                &*plan
                    .entries()
                    .iter()
                    .find(|p| p.entry_id() == id)
                    .unwrap()
                    .to_json()
                    .unwrap(),
                &*bytes
            );
            assert!(
                wrapper.entity()["items"].as_array().unwrap().iter().any(
                    |link| link["item"] == data_encoding::BASE64URL_NOPAD.encode(id.as_bytes())
                )
            );
        } else {
            assert!(!plan.entries().iter().any(|p| p.entry_id() == id));
        }
    }
    assert_eq!(*document.to_json().unwrap(), *original);
}

#[test]
fn wrapper_validation_failure_keeps_the_original_plan() {
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let mut plan = fixture().plan_import(&Wallet::default(), &mut rng).unwrap();
    let before: Vec<_> = plan
        .entries()
        .iter()
        .map(|p| p.to_json().unwrap())
        .collect();
    let report = plan.report();
    assert!(
        plan.wrap_collection(&"x".repeat(1024 * 1024), &mut rng)
            .is_err()
    );
    assert_eq!(plan.report(), report);
    assert_eq!(plan.entries().len(), before.len());
    for (payload, bytes) in plan.entries().iter().zip(before) {
        assert_eq!(*payload.to_json().unwrap(), *bytes);
    }
}

#[test]
fn empty_import_can_be_enclosed_for_an_original_file_attachment() {
    let document=Document::from_json(&serde_json::to_vec(&json!({"version":{"major":1,"minor":0},"exporterRpId":"example.test","exporterDisplayName":"Synthetic","timestamp":0,"accounts":[]})).unwrap()).unwrap();
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let mut plan = document.plan_import(&Wallet::default(), &mut rng).unwrap();
    let id = plan.wrap_collection("Empty export", &mut rng).unwrap();
    assert_eq!(plan.entries().len(), 1);
    assert_eq!(plan.entries()[0].entry_id(), id);
    assert_eq!(plan.entries()[0].entity()["items"], json!([]));
}
