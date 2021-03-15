use warp::Filter;
use crate::models::requests::{KeyRequest, KeyResponse};
use crate::models::key::PublicKey;
use crate::database::Database;
use std::sync::Arc;
use crate::database;
use crate::args::Args;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn request_keys_filter(db: Arc<Database>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("api"))
        .and(warp::path("request_keys"))
        .and(warp::body::content_length_limit(1024*16))
        .and(warp::body::json())
        .and(warp::any().map(move || db.clone()))
        .map(|key_request: KeyRequest, db: Arc<Database>| {
            let mut key_response = KeyResponse::default();
            for key_id in key_request.key_ids {
                let pk = db.fetch::<PublicKey>(key_id);

                if let Some(pk) = pk {
                    key_response.keys.push(pk);
                }
            }
            warp::reply::json(&key_response)
        })
}

pub async fn central_server(args: Args) {
    let db = database::Database::new(&args.database_path);

    let pk = PublicKey::new(0, vec![0; 16], "test".to_string());

    db.insert::<PublicKey>(pk);

    println!("Starting central server...");
    warp::serve(request_keys_filter(db))
        .run((Ipv4Addr::from_str(&args.address).unwrap(), args.port))
        .await;
}
