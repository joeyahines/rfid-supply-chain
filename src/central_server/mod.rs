use crate::args::{Args, CentralServerArgs};
use crate::config::import_config::ImportConfig;
use crate::database;
use crate::database::Database;
use crate::models::key::PublicKey;
use crate::models::requests::key_request::{KeyRequest, KeyResponse};
use openssl::rsa::Rsa;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use warp::Filter;
use crate::error::APIError;

fn request_keys_filter(
    db: Arc<Database>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("api"))
        .and(warp::path("request_keys"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and(warp::any().map(move || db.clone()))
        .map(|key_request: KeyRequest, db: Arc<Database>| {
            let mut key_response = KeyResponse::default();
            for key_id in key_request.key_ids {
                let pk = db.fetch::<PublicKey>(key_id);

                if let Some(pk) = pk {
                    key_response.keys.insert(key_id, pk);
                }
            }
            warp::reply::json(&key_response)
        })
}

pub async fn central_server(args: &Args, cent_args: &CentralServerArgs) -> Result<(), APIError> {
    let db = database::Database::new(&cent_args.database_path);

    if let Some(import) = &cent_args.import_path {
        let import_cfg = ImportConfig::new(import)?;

        for public_key in import_cfg.import {
            if Rsa::public_key_from_pem(&public_key.key).is_ok() {
                db.insert::<PublicKey>(public_key);
            } else {
                println!("{} has an invalid RSA key!", public_key.distributor_name)
            }
        }
    } else {
        println!("Starting central server...");
        warp::serve(request_keys_filter(db))
            .run((Ipv4Addr::from_str(&args.address).unwrap(), args.port))
            .await;
    }

    Ok(())
}
