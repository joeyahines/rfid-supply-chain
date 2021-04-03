use crate::args::{Args, CentralServerArgs};
use crate::config::import_config::ImportConfig;
use crate::database;
use crate::database::Database;
use crate::error::ApiError;
use models::central_record::CentralRecord;
use models::key::PublicKey;
use models::requests::key_request::{KeyRequest, KeyResponse};
use models::requests::update_record::{UpdateRecordRequest, UpdateRecordResponse};
use models::utility::open_private_key;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use warp::Filter;

fn request_keys_filter(
    db: Arc<Database>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path("api"))
        .and(warp::path("request_keys"))
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

fn update_record(
    db: Arc<Database>,
    private_key: Rsa<Private>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("api"))
        .and(warp::path("update_record"))
        .and(warp::body::json())
        .and(warp::any().map(move || db.clone()))
        .and(warp::any().map(move || private_key.clone()))
        .map(
            |update_req: UpdateRecordRequest, db: Arc<Database>, private_key: Rsa<Private>| {
                let mut keys = HashMap::new();

                for entry in update_req.rfid_data.entries.iter() {
                    keys.insert(entry.pub_key, db.fetch::<PublicKey>(entry.pub_key).unwrap());
                }

                let next_dist_key = db.fetch::<PublicKey>(update_req.next_dist_id).unwrap();

                if update_req
                    .rfid_data
                    .validate_chain(&keys, next_dist_key.clone())
                    .is_err()
                {
                    warp::reply::json(&UpdateRecordResponse {
                        record: None,
                        success: false,
                    })
                } else {
                    let chip_id = update_req.rfid_data.chip_data.chip_id;
                    let mut central_record = db
                        .fetch::<CentralRecord>(chip_id)
                        .unwrap_or_else(|| CentralRecord::new(chip_id));

                    central_record.add_entry(
                        private_key.private_key_to_pem().unwrap(),
                        update_req.dist_id,
                        update_req.next_dist_id,
                        next_dist_key.key,
                        update_req.rfid_data,
                    );

                    db.insert::<CentralRecord>(central_record.clone());

                    warp::reply::json(&UpdateRecordResponse {
                        record: Some(central_record),
                        success: true,
                    })
                }
            },
        )
}

pub async fn central_server(args: &Args, cent_args: &CentralServerArgs) -> Result<(), ApiError> {
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

        let private_key = open_private_key(cent_args.private_key.clone());

        warp::serve(request_keys_filter(db.clone()).or(update_record(db, private_key)))
            .run((Ipv4Addr::from_str(&args.address).unwrap(), args.port))
            .await;
    }

    Ok(())
}
