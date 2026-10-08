use anyhow::{bail, Result};
use std::{collections::HashMap, sync::Mutex};

/// Tracks parent waits made while a document loader owns its registry slot.
#[derive(Default)]
pub(crate) struct LoadDependencies {
    parents: Mutex<HashMap<String, String>>,
}

impl LoadDependencies {
    /// Call only from a slot's single-flight loader. The guard must span
    /// the parent attachment await, including cancellation and errors.
    pub(crate) fn begin<'a>(&'a self, doc: &str, parent: &str) -> Result<LoadDependency<'a>> {
        let mut parents = self.parents.lock().unwrap();
        let mut next = parent;
        loop {
            if next == doc {
                bail!("document load dependency cycle: {doc} -> {parent}");
            }
            match parents.get(next) {
                Some(parent) => next = parent,
                None => break,
            }
        }
        assert!(
            !parents.contains_key(doc),
            "a loader can wait on only one parent"
        );
        parents.insert(doc.to_string(), parent.to_string());
        Ok(LoadDependency {
            dependencies: self,
            doc: doc.to_string(),
        })
    }
}

pub(crate) struct LoadDependency<'a> {
    dependencies: &'a LoadDependencies,
    doc: String,
}

impl Drop for LoadDependency<'_> {
    fn drop(&mut self) {
        self.dependencies.parents.lock().unwrap().remove(&self.doc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_cycles_but_allows_shared_parents() {
        let dependencies = LoadDependencies::default();
        let _a = dependencies.begin("a", "b").unwrap();
        let _b = dependencies.begin("b", "c").unwrap();
        let _d = dependencies.begin("d", "c").unwrap();
        assert!(dependencies.begin("c", "a").is_err());
        assert!(dependencies.begin("c", "c").is_err());
        let _c = dependencies.begin("c", "root").unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_wait_removes_its_dependency() {
        let dependencies = LoadDependencies::default();
        let mut wait = Box::pin(async {
            let _guard = dependencies.begin("a", "b").unwrap();
            std::future::pending::<()>().await;
        });
        assert!(futures::poll!(wait.as_mut()).is_pending());
        assert!(dependencies.begin("b", "a").is_err());
        drop(wait);
        let _guard = dependencies.begin("b", "a").unwrap();
    }
}
