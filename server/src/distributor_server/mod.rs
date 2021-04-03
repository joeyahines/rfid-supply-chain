use crate::args::{Args, DistributorServerArgs};
use crate::error::ApiError;
use models::requests::key_request::{KeyRequest, KeyResponse};
use models::requests::update_blockchain::UpdateBlockChainRequest;
use models::requests::update_record::{UpdateRecordRequest, UpdateRecordResponse};
use models::rfid::{RfidBuilder, RfidData};
use models::utility::open_private_key;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use reqwest::Url;
use std::net::Ipv4Addr;
use std::str::FromStr;
use warp::Filter;

async fn update_record(
    client: reqwest::Client,
    central_server_addr: Url,
    dist_id: u32,
    next_dist_id: u32,
    rfid_data: RfidData,
    private_key: Rsa<Private>,
) -> Result<UpdateRecordResponse, ApiError> {
    let req = UpdateRecordRequest::new(dist_id, next_dist_id, rfid_data, &private_key);
    let url = central_server_addr.join("api/update_record").unwrap();

    Ok(client.post(url).json(&req).send().await?.json().await?)
}

async fn update_blockchain(
    request: UpdateBlockChainRequest,
    central_server_addr: Url,
    key_id: u32,
    private_key: Rsa<Private>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let url = central_server_addr.join("api/request_keys").unwrap();

    let client = reqwest::Client::new();

    let mut pk_ids: Vec<u32> = request
        .rfid_data
        .entries
        .iter()
        .map(|entry| entry.pub_key)
        .collect();

    pk_ids.push(request.next_distributor);
    pk_ids.push(key_id);

    let key_request = KeyRequest { key_ids: pk_ids };

    let res: KeyResponse = client
        .get(url)
        .json(&key_request)
        .send()
        .await
        .map_err(|e| warp::reject::custom(ApiError::from(e)))?
        .json()
        .await
        .map_err(|e| warp::reject::custom(ApiError::from(e)))?;

    let rfid_builder = RfidBuilder::from(request.rfid_data);

    let rfid_data = rfid_builder
        .add_entry(
            private_key.private_key_to_pem().unwrap(),
            key_id,
            request.next_distributor,
            &res.keys,
        )
        .build();

    Ok(
        match rfid_data.validate_chain(
            &res.keys,
            res.keys.get(&request.next_distributor).unwrap().clone(),
        ) {
            Ok(_) => {
                update_record(
                    client,
                    central_server_addr,
                    key_id,
                    request.next_distributor,
                    rfid_data.clone(),
                    private_key,
                )
                .await?;
                serde_json::to_string(&rfid_data).unwrap()
            }
            Err(e) => format!("Failed to validate at position {}", e),
        },
    )
}

fn update_blockchain_filter(
    central_server_addr: Url,
    key_id: u32,
    key: Rsa<Private>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::post()
        .and(warp::path("api"))
        .and(warp::path("update_blockchain"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and(warp::any().map(move || central_server_addr.clone()))
        .and(warp::any().map(move || key_id))
        .and(warp::any().map(move || key.clone()))
        .and_then(update_blockchain)
}

pub async fn distributor_server(
    args: &Args,
    dist_args: &DistributorServerArgs,
) -> Result<(), ApiError> {
    let private_key = open_private_key(dist_args.private_key.clone());
    println!("Starting dist server...");
    warp::serve(update_blockchain_filter(
        Url::from_str(dist_args.central_server_addr.as_str()).unwrap(),
        dist_args.key_id,
        private_key,
    ))
    .run((Ipv4Addr::from_str(&args.address).unwrap(), args.port))
    .await;

    Ok(())
}
