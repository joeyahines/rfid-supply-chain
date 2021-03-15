use sled::{open, Db};
use std::path::Path;
use std::sync::Arc;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait DatabaseModel: Serialize + DeserializeOwned {
    type ID;

    fn id(&self) -> Self::ID;
    fn set_id(&mut self, id: Self::ID);

    fn id_to_bytes(self) -> Vec<u8> {
        Self::id_type_to_bytes(self.id())
    }

    fn id_type_to_bytes(id: Self::ID) -> Vec<u8>;
    fn tree() -> String;
}

pub struct Database {
    db: Db,
}

impl Database {
    pub fn new(db_path: &Path) -> Arc<Database> {
        let db = open(db_path).unwrap();
        Arc::new(Self { db })
    }

    pub fn insert<T>(&self, model: T) where T: DatabaseModel {
        let json = serde_json::to_vec(&model).unwrap();
        let tree = self.db.open_tree(T::tree()).unwrap();
        tree.insert(model.id_to_bytes(), json).unwrap();
    }

    pub fn fetch<T>(&self, id: T::ID) -> Option<T> where T: DatabaseModel {
        let tree = self.db.open_tree(T::tree()).unwrap();
        let bytes = tree.get(T::id_type_to_bytes(id)).unwrap();

        if let Some(bytes) = bytes {
            Some(serde_json::from_slice::<T>(&bytes).unwrap())
        }
        else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::database::Database;
    use std::path::Path;
    use crate::models::key::PublicKey;

    #[test]
    fn test_db() {
        let db = Database::new(Path::new("test_db"));
        let public_key = PublicKey::new(0, vec![0, 1], "dist1".to_string());
        db.insert::<PublicKey>(public_key.clone());

        let public_key2 = db.fetch::<PublicKey>(public_key.id);

        assert_eq!(public_key.id, public_key2.id);

        db.db.clear().unwrap();
    }
}