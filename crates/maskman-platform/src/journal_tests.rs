use std::path::PathBuf;

use super::{create_temporary, JournalEntry, NetworkJournal, NEXT_TEMP_FILE};
use std::sync::atomic::Ordering;

#[test]
fn journal_drains_owned_resources_in_reverse_order() {
    let mut journal = NetworkJournal::default();
    journal.record(JournalEntry::Tun { name: "maskman0".into() });
    journal.record(JournalEntry::Route { destination: "0.0.0.0/0".into(), interface_index: 7 });
    let entries = journal.drain_reverse().collect::<Vec<_>>();
    assert!(matches!(entries[0], JournalEntry::Route { .. }));
    assert!(matches!(entries[1], JournalEntry::Tun { .. }));
    assert!(journal.is_empty());
}

#[test]
fn journal_round_trips_with_private_file_permissions() {
    let path = std::env::temp_dir().join(format!("maskman-journal-{}", std::process::id()));
    let mut journal = NetworkJournal::default();
    let tun_name = if cfg!(target_os = "macos") { "utun9" } else { "maskman0" };
    journal.record(JournalEntry::Tun { name: tun_name.into() });
    journal.persist(&path).unwrap_or_else(|error| panic!("persist journal: {error}"));
    let loaded =
        NetworkJournal::load(&path).unwrap_or_else(|error| panic!("load journal: {error}"));
    assert_eq!(loaded.entries(), journal.entries());
    NetworkJournal::remove(&path).unwrap_or_else(|error| panic!("remove journal: {error}"));
    assert!(!PathBuf::from(&path).exists());
}

#[test]
fn concurrent_temporary_files_are_exclusive() {
    let root =
        std::env::temp_dir().join(format!("maskman-journal-temporary-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create temp root: {error}"));
    let (first, first_file) = create_temporary(&root, "journal.json")
        .unwrap_or_else(|error| panic!("reserve first temp: {error}"));
    let (second, second_file) = create_temporary(&root, "journal.json")
        .unwrap_or_else(|error| panic!("reserve second temp: {error}"));
    assert_ne!(first, second);
    drop((first_file, second_file));
    std::fs::remove_dir_all(root).unwrap_or_else(|error| panic!("remove temp root: {error}"));
}

#[test]
fn prepare_persists_ownership_before_mutation() {
    let path = std::env::temp_dir().join(format!(
        "maskman-journal-prepare-{}-{}.json",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let mut journal = NetworkJournal::default();
    journal
        .prepare(JournalEntry::NatPending { table: crate::managed_nat_resource_id().into() }, &path)
        .unwrap_or_else(|error| panic!("prepare journal: {error}"));
    let loaded = NetworkJournal::load(&path)
        .unwrap_or_else(|error| panic!("load prepared journal: {error}"));
    assert!(matches!(loaded.entries(), [JournalEntry::NatPending { .. }]));
    NetworkJournal::remove(&path).unwrap_or_else(|error| panic!("remove journal: {error}"));
}

#[test]
fn promotion_replaces_pending_with_active_entry() {
    let path = std::env::temp_dir().join(format!(
        "maskman-journal-promote-{}-{}.json",
        std::process::id(),
        NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let pending = JournalEntry::NatPending { table: crate::managed_nat_resource_id().into() };
    let active = JournalEntry::Nat { table: crate::managed_nat_resource_id().into() };
    let mut journal = NetworkJournal::default();
    journal
        .prepare(pending.clone(), &path)
        .unwrap_or_else(|error| panic!("prepare journal: {error}"));
    journal
        .promote_last(pending, active.clone(), &path)
        .unwrap_or_else(|error| panic!("promote journal: {error}"));
    let loaded = NetworkJournal::load(&path)
        .unwrap_or_else(|error| panic!("load promoted journal: {error}"));
    assert_eq!(loaded.entries(), &[active]);
    NetworkJournal::remove(&path).unwrap_or_else(|error| panic!("remove journal: {error}"));
}

#[test]
fn failed_promotion_keeps_durable_pending_entry() {
    let root = std::env::temp_dir().join(format!(
        "maskman-journal-promotion-failure-{}-{}",
        std::process::id(),
        NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root)
        .unwrap_or_else(|error| panic!("create promotion test root: {error}"));
    let path = root.join("journal.json");
    let bad_path = root.join("occupied");
    std::fs::create_dir(&bad_path)
        .unwrap_or_else(|error| panic!("create occupied promotion path: {error}"));
    let pending = JournalEntry::NatPending { table: crate::managed_nat_resource_id().into() };
    let active = JournalEntry::Nat { table: crate::managed_nat_resource_id().into() };
    let mut journal = NetworkJournal::default();
    journal
        .prepare(pending.clone(), &path)
        .unwrap_or_else(|error| panic!("prepare journal: {error}"));
    assert!(journal.promote_last(pending.clone(), active, &bad_path).is_err());
    let loaded = NetworkJournal::load(&path)
        .unwrap_or_else(|error| panic!("load pending journal after promotion failure: {error}"));
    assert_eq!(loaded.entries(), &[pending]);
    NetworkJournal::remove(&path).unwrap_or_else(|error| panic!("remove journal: {error}"));
    std::fs::remove_dir_all(&root)
        .unwrap_or_else(|error| panic!("remove promotion test root: {error}"));
}

#[test]
fn pending_cleanup_only_removes_the_journal_record() {
    let path = std::env::temp_dir().join(format!(
        "maskman-journal-pending-cleanup-{}-{}.json",
        std::process::id(),
        NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut journal = NetworkJournal::default();
    journal.record(JournalEntry::NatPending { table: crate::managed_nat_resource_id().into() });
    journal.persist(&path).unwrap_or_else(|error| panic!("persist pending journal: {error}"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap_or_else(|error| panic!("build runtime: {error}"));
    let report = runtime
        .block_on(super::cleanup(&path, false))
        .unwrap_or_else(|error| panic!("cleanup pending journal: {error}"));
    assert_eq!(report.inspected, 1);
    assert_eq!(report.removed, 1);
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn journal_persist_rejects_a_broken_symlink() {
    use std::os::unix::fs::symlink;

    let root = std::env::temp_dir().join(format!(
        "maskman-journal-symlink-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let path = root.join("journal.json");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create test root: {error}"));
    symlink(root.join("missing.json"), &path)
        .unwrap_or_else(|error| panic!("create broken journal symlink: {error}"));
    assert!(NetworkJournal::default().persist(&path).is_err());
    assert!(std::fs::symlink_metadata(&path)
        .unwrap_or_else(|error| panic!("inspect journal symlink: {error}"))
        .file_type()
        .is_symlink());
    std::fs::remove_dir_all(root).unwrap_or_else(|error| panic!("remove test root: {error}"));
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_route_json_without_named_interface_still_loads() {
    let path = std::env::temp_dir().join(format!(
        "maskman-journal-legacy-route-{}-{}.json",
        std::process::id(),
        NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let contents = br#"{"version":1,"entries":[{"kind":"route","destination":"0.0.0.0/0","interface_index":7}]}"#;
    std::fs::write(&path, contents).unwrap_or_else(|error| panic!("write legacy journal: {error}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("protect legacy journal: {error}"));
    }
    let loaded =
        NetworkJournal::load(&path).unwrap_or_else(|error| panic!("load legacy journal: {error}"));
    assert!(matches!(loaded.entries(), [JournalEntry::Route { .. }]));
    NetworkJournal::remove(&path).unwrap_or_else(|error| panic!("remove journal: {error}"));
}

#[cfg(target_os = "macos")]
#[test]
fn legacy_numeric_route_is_rejected_on_macos() {
    let path = std::env::temp_dir().join(format!(
        "maskman-journal-legacy-route-macos-{}-{}.json",
        std::process::id(),
        NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let contents = br#"{"version":1,"entries":[{"kind":"route","destination":"0.0.0.0/0","interface_index":7}]}"#;
    std::fs::write(&path, contents).unwrap_or_else(|error| panic!("write legacy journal: {error}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("protect legacy journal: {error}"));
    }
    assert!(NetworkJournal::load(&path).is_err());
    NetworkJournal::remove(&path).unwrap_or_else(|error| panic!("remove journal: {error}"));
}
