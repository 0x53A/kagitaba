use super::*;
use kagitaba_store::index::CollectionNode;
use std::collections::BTreeSet;

impl App {
    pub(super) fn entry_collection_paths(&self, id: EntryId) -> Vec<String> {
        let mut paths = Vec::new();
        for row in self.index_rows.values() {
            if let Some(root) = &row.collection {
                membership_paths(root, id, &mut Vec::new(), &mut paths);
            }
        }
        paths.sort();
        paths
    }

    pub(super) fn selected_collection(&self) -> Option<&CollectionNode> {
        let (owner, path) = self.collection_selection.as_ref()?;
        let mut node = self.index_rows.get(owner)?.collection.as_ref()?;
        for index in path { node = node.children.get(*index)?; }
        Some(node)
    }

    pub(super) fn filed_entries(&self) -> BTreeSet<EntryId> {
        fn collect(node: &CollectionNode, entries: &mut BTreeSet<EntryId>) {
            entries.extend(node.entries.iter().copied());
            for child in &node.children { collect(child, entries); }
        }
        let mut entries = BTreeSet::new();
        for row in self.index_rows.values() {
            if let Some(node) = &row.collection { collect(node, &mut entries); }
        }
        entries
    }

    pub(super) fn select_collection(&mut self, selection: Option<(EntryId, Vec<usize>)>, unfiled: bool) {
        self.collection_selection = selection;
        self.unfiled_selection = unfiled;
        self.entry_generation = self.entry_generation.wrapping_add(1);
    }

    pub(super) fn collection_tree(&mut self, ui: &mut egui::Ui) {
        if ui.selectable_label(self.collection_selection.is_none() && !self.unfiled_selection, "All entries").clicked() {
            self.select_collection(None, false);
        }
        if ui.selectable_label(self.unfiled_selection, "Entries not in a collection").on_hover_text("Membership in readable, indexed collections").clicked() {
            self.select_collection(None, true);
        }
        ui.separator();
        if let Some((owner, _)) = self.collection_selection.as_ref() {
            let owner = *owner;
            if ui.button("Edit collection").clicked() { self.navigate(Leave::Select(owner)); }
            if let Some(node) = self.selected_collection() {
                let missing = node.unresolved_links + node.entries.iter().filter(|id| !self.index_rows.get(id).is_some_and(|row| row.kind == kagitaba_cxf::PayloadKind::Item)).count();
                if missing > 0 { theme::caption(ui, format!("{missing} unavailable links")); }
            }
        }
        let mut selection = None;
        let mut roots: Vec<_> = self.index_rows.iter().filter_map(|(id,row)| row.collection.as_ref().map(|node| (*id,node))).collect();
        roots.sort_by(|(left_id,left),(right_id,right)| left.title.cmp(&right.title).then(left_id.cmp(right_id)));
        egui::ScrollArea::vertical().id_salt("collection-tree").max_height(ui.available_height().max(80.0)).show(ui, |ui| {
            for (owner, node) in roots {
                node_ui(ui, owner, &mut Vec::new(), node, self.collection_selection.as_ref(), &mut selection);
            }
        });
        if let Some(selection) = selection { self.select_collection(Some(selection), false); }
    }
}

fn node_ui(ui: &mut egui::Ui, owner: EntryId, path: &mut Vec<usize>, node: &CollectionNode, selected: Option<&(EntryId, Vec<usize>)>, clicked: &mut Option<(EntryId, Vec<usize>)>) {
    let key = (owner, path.clone());
    ui.push_id(&key, |ui| {
        let label = if node.title.is_empty() { "Untitled collection" } else { &node.title };
        if node.children.is_empty() {
            if ui.selectable_label(selected == Some(&key), label).clicked() { *clicked = Some(key.clone()); }
        } else {
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), ui.id().with("children"), true)
                .show_header(ui, |ui| {
                    if ui.selectable_label(selected == Some(&key), label).clicked() { *clicked = Some(key.clone()); }
                }).body(|ui| {
                    for (index, child) in node.children.iter().enumerate() {
                        path.push(index);
                        node_ui(ui, owner, path, child, selected, clicked);
                        path.pop();
                    }
                });
        }
    });
}

fn membership_paths(node: &CollectionNode, id: EntryId, ancestors: &mut Vec<String>, paths: &mut Vec<String>) {
    ancestors.push(if node.title.is_empty() { "Untitled collection".into() } else { node.title.clone() });
    if node.entries.contains(&id) { paths.push(ancestors.join(" › ")); }
    for child in &node.children { membership_paths(child, id, ancestors, paths); }
    ancestors.pop();
}

#[cfg(test)]
mod membership_tests {
    use super::*;
    #[test]
    fn paths_include_direct_memberships_without_inventing_ancestor_membership() {
        let id = EntryId::from_bytes([7;16]);
        let child = |title: &str| CollectionNode { id: vec![1], title: title.into(), entries: vec![id], unresolved_links: 1, children: vec![] };
        let root = CollectionNode { id: vec![2], title: "Root".into(), entries: vec![], unresolved_links: 1, children: vec![child("Child"), child("")] };
        let mut paths = Vec::new();
        membership_paths(&root, id, &mut Vec::new(), &mut paths);
        membership_paths(&child("Other root"), id, &mut Vec::new(), &mut paths);
        assert_eq!(paths, ["Root › Child", "Root › Untitled collection", "Other root"]);
        paths.clear();
        membership_paths(&root, EntryId::from_bytes([8;16]), &mut Vec::new(), &mut paths);
        assert!(paths.is_empty());
    }
}
