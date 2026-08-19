#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalEntry {
    Tun { name: String },
    Route { destination: String, interface_index: u32 },
    Nat { table: String },
}

#[derive(Debug, Default)]
pub struct NetworkJournal {
    entries: Vec<JournalEntry>,
}

impl NetworkJournal {
    pub fn record(&mut self, entry: JournalEntry) {
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    pub fn drain_reverse(&mut self) -> impl DoubleEndedIterator<Item = JournalEntry> + '_ {
        self.entries.drain(..).rev()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{JournalEntry, NetworkJournal};

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
}
