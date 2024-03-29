use sled::{open, Db};
use std::path::Path;
use std::sync::Arc;
use models::DatabaseModel;

pub struct Database {
    db: Db,
}

impl Database {
    pub fn new(db_path: &Path) -> Arc<Database> {
        let db = open(db_path).unwrap();
        Arc::new(Self { db })
    }

    pub fn insert<T>(&self, model: T)
    where
        T: DatabaseModel,
    {
        let json = serde_json::to_vec(&model).unwrap();
        let tree = self.db.open_tree(T::tree()).unwrap();
        tree.insert(model.id_to_bytes(), json).unwrap();
    }

    pub fn fetch<T>(&self, id: T::ID) -> Option<T>
    where
        T: DatabaseModel,
    {
        let tree = self.db.open_tree(T::tree()).unwrap();
        let bytes = tree.get(T::id_type_to_bytes(id)).unwrap();

        if let Some(bytes) = bytes {
            Some(serde_json::from_slice::<T>(&bytes).unwrap())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::database::Database;
    use crate::models::key::PublicKey;
    use std::path::Path;

    #[test]
    fn test_db() {
        let db = Database::new(Path::new("test_db"));
        let public_key = PublicKey::new(0, vec![0, 1], "dist1".to_string());
        db.insert::<PublicKey>(public_key.clone());

        let public_key2 = db.fetch::<PublicKey>(public_key.id).unwrap();

        assert_eq!(public_key.id, public_key2.id);

        db.db.clear().unwrap();
    }
}
