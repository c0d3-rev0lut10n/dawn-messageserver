/*	Copyright (c) 2022-2024 Laurenz Werner
	
	This file is part of Dawn.
	
	Dawn is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	Dawn is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with Dawn.  If not, see <http://www.gnu.org/licenses/>.
*/

#[macro_use]
extern crate lazy_static;

mod handles;
mod internal;
mod request_schemes;
mod response_schemes;

use handles::*;
use internal::*;
use request_schemes::*;

use actix_web::{get, post, delete, web, App, HttpResponse, HttpServer, Responder};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::path::PathBuf;
use std::time::Duration;
use serde::Serialize;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use regex::Regex;
use hex::{encode, decode};
use futures::StreamExt;
use chrono::prelude::*;
use std::array::TryFromSliceError;
use fs4::tokio::AsyncFileExt;
use moka::future::Cache;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as BASE64};

// constants, planned to be read from config file in a later version
const RUNTIME_DIR: &str = "./runtime";
const SERVER_ADDRESS: &str = "127.0.0.1";
const SERVER_PORT: u16 = 8080;
const MAX_SND_SIZE: usize = 256_000;
const SAVED_MSG_MINIMUM: usize = 28;

lazy_static! {
	// globally defined regex patterns
	static ref IS_HEX: Regex = Regex::new("^[0-9a-f]+$").unwrap();
	static ref IS_HANDLE: Regex = Regex::new("^[0-9a-zA-Z_-]+$").unwrap();
	static ref IS_MDC: Regex = Regex::new("^[0-9a-f]{8}$").unwrap();
	static ref IS_INIT_SECRET: Regex = Regex::new("^[0-9a-zA-Z]{16}$").unwrap();
	// pattern for deleted messages
	static ref DELETED: Vec<u8> = vec![255];

}

// log macros
#[macro_export]
macro_rules! info {
	($a:expr) => {
		println!("[INFO] {}", $a)
	}
}

// server error return macro
#[macro_export]
macro_rules! return_server_error {
	() => {
		return HttpResponse::InternalServerError().content_type("text/plain").body("Internal server error")
	}
}

// client error return macro
#[macro_export]
macro_rules! return_client_error {
	($a:expr) => {
		return HttpResponse::BadRequest().content_type("text/plain").body($a)
	}
}

// byte return macro
#[macro_export]
macro_rules! return_bytes {
	($a:expr) => {
		return HttpResponse::Ok().content_type("application/octet-stream").body($a)
	}
}

// zero return macro
#[macro_export]
macro_rules! return_zero {
	() => {
		return HttpResponse::NoContent().finish()
	}
}

#[derive(Clone)]
struct Listener {
	subscriptions: Vec<u128>,
}

#[derive(Clone)]
struct Subscription {
	messages: Vec<MessageInfo>,
	mdc_map: HashMap<String, Vec<u8>>
}

#[derive(Serialize, Clone)]
struct MessageInfo {
	id: String,
	message_number: u16,
}

#[derive(Serialize)]
struct Messages {
	messages: Vec<SubscriptionMessage>
}

#[derive(Serialize)]
struct SubscriptionMessage {
	status: String,
	message: Option<MessageData>
}

#[derive(Serialize)]
struct MessageData {
	id: String,
	msg_number: u16,
	sent: i64,
	read: i64,
	content: String
}

struct IdLock {
	status: bool,
}

struct HandleLock {
	status: bool,
}

struct OtiLock {
	status: bool,
}

// receive specified message
#[get("/rcv/{id}/{msg_number}")]
async fn rcv(req: web::Path<ReceiveRequestScheme>, query: web::Query<OptionalMDCQuery>) -> impl Responder {
	// check if id is hex-string
	if !IS_HEX.is_match(&req.id) { return_client_error!("parsing error"); }
	
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push(&req.id);
	path.push(&req.msg_number.to_string());
	if !path.is_file() {
		// message does not exist
		return_zero!();
	}
	
	// message does exist
	let message_file = File::open(&path).await;
	if message_file.is_err() { return_server_error!(); }
	let mut message_file = message_file.unwrap();
	
	if message_file.lock_shared().is_err() { return_server_error!(); }
	
	let mut file_bytes = vec![];
	if message_file.read_to_end(&mut file_bytes).await.is_err() {
		message_file.unlock().ok();
		return_server_error!();
	}
	
	if message_file.unlock().is_err() { return_server_error!(); }
	
	if file_bytes.len() <= SAVED_MSG_MINIMUM {
		if file_bytes == DELETED.to_vec() {
			// message got deleted
			return HttpResponse::NoContent().insert_header(("X-Deleted", "true")).finish();
		}
		return_server_error!();
	}
	
	let (_, message) = file_bytes.split_at(SAVED_MSG_MINIMUM);
	
	if query.mdc.is_some() {
		let query_mdc = query.mdc.clone().unwrap();
		if !IS_MDC.is_match(&query_mdc) { return_client_error!("invalid mdc"); }
		let mdc = &file_bytes[0..4];
		if query_mdc != encode(mdc) {
			return_client_error!("wrong mdc");
		}
		let info = &file_bytes[4..28];
		let sent_timestamp_slice: &[u8;8] = &info[0..8].try_into().unwrap();
		let read_timestamp_slice: &[u8;8] = &info[8..16].try_into().unwrap();
		let referrer = &info[16..24];
		let sent_timestamp = i64::from_le_bytes(*sent_timestamp_slice);
		
		// respond to the request
		let mut response = HttpResponse::Ok();
		response.content_type("application/octet-stream");
		response.insert_header(("X-Sent", sent_timestamp.to_string()));
		if referrer != [0u8;8] {
			// there is a well-defined referrer, return it
			response.insert_header(("X-Referrer", encode(referrer)));
		}
		if read_timestamp_slice == &[0u8;8] {
			// message was never marked as read
			return response.body(message.to_vec());
		}
		let read_timestamp = i64::from_le_bytes(*read_timestamp_slice);
	
		response.insert_header(("X-Read", read_timestamp.to_string()));
		return response.body(message.to_vec());
	}
	
	return_bytes!(message.to_vec());
}

// get details for a message, currently the timestamp it was sent and the timestamp it was marked as read
#[get("/d/{id}/{msg_number}")]
async fn d(req: web::Path<ReceiveRequestScheme>, query: web::Query<MDCQuery>) -> impl Responder {
	// check if id is hex-string
	if !IS_HEX.is_match(&req.id) { return_client_error!("parsing error"); }
	
	// check if message detail code is valid
	if !IS_MDC.is_match(&query.mdc) { return_client_error!("invalid mdc"); }
	
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push(&req.id);
	path.push(&req.msg_number.to_string());
	if !path.is_file() {
		// message does not exist
		return_zero!();
	}
	
	// message does exist
	let message_file = File::open(&path).await;
	if message_file.is_err() { return_server_error!(); }
	let mut message_file = message_file.unwrap();
	
	if message_file.lock_shared().is_err() { return_server_error!(); }
	
	let mut file_bytes = vec![];
	if message_file.read_to_end(&mut file_bytes).await.is_err() {
		message_file.unlock().ok();
		return_server_error!();
	}
	
	if message_file.unlock().is_err() { return_server_error!(); }
	
	if file_bytes.len() <= SAVED_MSG_MINIMUM {
		if file_bytes == DELETED.to_vec() {
			// message got deleted
			return HttpResponse::NoContent().insert_header(("X-Deleted", "true")).finish();
		}
		return_server_error!();
	}
	let (mdc, info) = file_bytes.split_at(4);
	
	// verify mdc
	if query.mdc != encode(mdc) {
		return_client_error!("wrong mdc");
	}
	
	// split off timestamps and referrer
	let (timestamps_and_referrer_bytes, _) = info.split_at(24);
	let (timestamps_bytes, referrer) = timestamps_and_referrer_bytes.split_at(16);
	let (sent_timestamp_bytes, read_timestamp_bytes) = timestamps_bytes.split_at(8);
	
	// parse 'sent' timestamp
	let sent_timestamp_slice: Result<[u8;8], TryFromSliceError> = sent_timestamp_bytes.to_owned().as_slice().try_into();
	if sent_timestamp_slice.is_err() { return_server_error!(); }
	let sent_timestamp = i64::from_le_bytes(sent_timestamp_slice.unwrap());
	
	// parse 'read' timestamp
	let read_timestamp_slice: Result<[u8;8], TryFromSliceError> = read_timestamp_bytes.to_owned().as_slice().try_into();
	if read_timestamp_slice.is_err() { return_server_error!(); }
	let read_timestamp_slice = read_timestamp_slice.unwrap();
	
	// respond to the request
	let mut response = HttpResponse::Ok();
	response.insert_header(("X-Sent", sent_timestamp.to_string()));
	if referrer != [0u8;8].to_vec() {
		// there is a well-defined referrer, return it
		response.insert_header(("X-Referrer", encode(referrer)));
	}
	if read_timestamp_slice == [0u8;8] {
		// message was never marked as read
		return response.finish();
	}
	let read_timestamp = i64::from_le_bytes(read_timestamp_slice);

	response.insert_header(("X-Read", read_timestamp.to_string()));
	response.finish()
}

// mark a message as read
#[get("/read/{id}/{msg_number}")]
async fn read(req: web::Path<ReceiveRequestScheme>, query: web::Query<MDCQuery>) -> impl Responder {
	// check if id is hex-string
	if !IS_HEX.is_match(&req.id) { return_client_error!("parsing error"); }
	
	// check if message detail code is valid
	if !IS_MDC.is_match(&query.mdc) { return_client_error!("invalid mdc"); }
	
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push(&req.id);
	path.push(&req.msg_number.to_string());
	if !path.is_file() {
		// message does not exist
		return_zero!();
	}
	
	// message does exist
	let message_file = File::open(&path).await;
	if message_file.is_err() { return_server_error!(); }
	let mut message_file = message_file.unwrap();
	
	if message_file.lock_exclusive().is_err() { return_server_error!(); } // lock exclusive as we will write to the file
	
	let mut file_bytes = vec![];
	if message_file.read_to_end(&mut file_bytes).await.is_err() {
		message_file.unlock().ok();
		return_server_error!();
	}
	
	if file_bytes.len() <= SAVED_MSG_MINIMUM {
		message_file.unlock().ok();
		if file_bytes == DELETED.to_vec() {
			// message got deleted
			return HttpResponse::NoContent().insert_header(("X-Deleted", "true")).finish();
		}
		return_server_error!();
	}
	let (mdc, info) = file_bytes.split_at(4);
	
	// verify mdc
	if query.mdc != encode(mdc) {
		message_file.unlock().ok();
		return_client_error!("wrong mdc");
	}
	
	// split off timestamp
	let (timestamps_bytes, message) = info.split_at(16);
	let (sent_timestamp_bytes, read_timestamp_bytes) = timestamps_bytes.split_at(8);
	
	// parse 'read' timestamp
	let read_timestamp_slice: Result<[u8;8], TryFromSliceError> = read_timestamp_bytes.to_owned().as_slice().try_into();
	if read_timestamp_slice.is_err() {
		message_file.unlock().ok();
		return_server_error!();
	}
	let read_timestamp_slice = read_timestamp_slice.unwrap();
	
	if read_timestamp_slice != [0u8;8] {
		// message is already marked as read
		message_file.unlock().ok();
		return_client_error!("message was already read");
	}
	
	let mut read_timestamp = Utc::now().timestamp().to_le_bytes().to_vec();
	
	let mut new_file_bytes = mdc.to_vec();
	new_file_bytes.append(&mut sent_timestamp_bytes.to_vec());
	new_file_bytes.append(&mut read_timestamp);
	new_file_bytes.append(&mut message.to_vec());
	let new_file = OpenOptions::new().write(true).truncate(true).open(&path).await;
	
	if new_file.is_err() {
		message_file.unlock().ok();
		return_server_error!();
	}
	
	let mut new_file = new_file.unwrap();
	
	if new_file.write_all(&new_file_bytes).await.is_err() || new_file.flush().await.is_err() {
		message_file.unlock().ok();
		return_server_error!();
	}
			
	if message_file.unlock().is_err() { return_server_error!(); }
	
	HttpResponse::Ok().finish()
}

// send message to id with message detail code in query string and content in body
#[post("/snd/{id}")]
async fn snd(req: web::Path<SendRequestScheme>, query: web::Query<SendQuery>, mut payload: web::Payload, subscription_cache: web::Data<Cache<u128, Arc<RwLock<Subscription>>>>, listener_cache: web::Data<Cache<String, Arc<RwLock<Listener>>>>) -> impl Responder {
	let mut body = web::BytesMut::new();
	while let Some(chunk) = payload.next().await {
		if chunk.is_err() {
			return_client_error!("network error");
		};
		let chunk = chunk.unwrap();
		if (body.len() + chunk.len()) > MAX_SND_SIZE {
			return_client_error!("request body over max upload size");
		}
		body.extend_from_slice(&chunk);
	}
	// catch empty messages
	if body.is_empty() { return_client_error!("empty body"); }
	// check if id is hex-string
	if !IS_HEX.is_match(&req.id) { return_client_error!("invalid id"); }
	// check if mdc in query string is valid
	if !IS_MDC.is_match(&query.mdc) { return_client_error!("invalid message detail code"); }
	// check and decode referrer if needed
	let mut referrer;
	if query.referrer.is_some() {
		let referrer_from_query = query.referrer.clone().unwrap();
		if referrer_from_query.len() != 16 {
			return_client_error!("invalid referrer length");
		}
		let referrer_result = decode(referrer_from_query);
		if referrer_result.is_err() {
			return_client_error!("invalid referrer");
		}
		else {
			referrer = referrer_result.unwrap().to_vec();
		}
	}
	else {
		referrer = [0u8;8].to_vec();
	}
	// get current time
	let mut time = Utc::now().timestamp().to_le_bytes().to_vec();
	// prepare the placeholder for the time read
	let mut read_time_placeholder = [0u8;8].to_vec();
	
	let msg_number;
	
	// get file path, planned to use database in a later version
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push(&req.id);
	if !path.exists() {
		// first message for id, therefore create directory
		if fs::create_dir(path).await.is_err() { return_server_error!(); }
		
		// set message number
		msg_number = 0;
		
		// save number of messages to file
		let mut number_file = PathBuf::from(RUNTIME_DIR);
		number_file.push(&req.id);
		number_file.push("msg_number");
		let msg_number_file_result = File::create(number_file).await;
		if msg_number_file_result.is_err() { return_server_error!(); }
		let mut msg_number_file = msg_number_file_result.unwrap();
		
		if msg_number_file.lock_exclusive().is_err() { return_server_error!(); }
		
		if msg_number_file.write_all("0".as_bytes()).await.is_err() {
			msg_number_file.unlock().ok();
			return_server_error!();
		}
		
		if msg_number_file.unlock().is_err() { return_server_error!(); }	
	}
	else {
		// there are already messages for this id
		let mut msg_number_path = PathBuf::from(RUNTIME_DIR);
		msg_number_path.push(&req.id);
		msg_number_path.push("msg_number");
		
		// lock exclusively to prevent race conditions
		let msg_number_file = OpenOptions::new().read(true).open(&msg_number_path).await;
		if msg_number_file.is_err() { return_server_error!(); }
		let mut msg_number_file = msg_number_file.unwrap();
		
		if msg_number_file.lock_exclusive().is_err() { return_server_error!(); }
		
		let mut number_bytes = vec![];
		if msg_number_file.read_to_end(&mut number_bytes).await.is_err() {
			msg_number_file.unlock().ok();
			return_server_error!();
		}
		
		msg_number = String::from_utf8_lossy(&number_bytes).into_owned().parse().unwrap_or(0) + 1;
		
		if msg_number > 60000 {
			if msg_number_file.unlock().is_err() { return_server_error!(); }
			return_client_error!("Too many messages");
		}
		
		let truncate_number_file = OpenOptions::new().write(true).truncate(true).open(&msg_number_path).await;
		if truncate_number_file.is_err() || truncate_number_file.unwrap().write_all(msg_number.to_string().as_bytes()).await.is_err() || msg_number_file.flush().await.is_err() {
			msg_number_file.unlock().ok();
			return_server_error!();
		}
		
		if msg_number_file.unlock().is_err() { return_server_error!(); }
	}
	
	let mut msg_path = PathBuf::from(RUNTIME_DIR);
	msg_path.push(&req.id);
	msg_path.push(&msg_number.to_string());
	// write content and mdc to file
	let file_bytes = decode(&query.mdc);
	if file_bytes.is_err() { return_client_error!("invalid message detail code"); }
	
	let mut file_bytes = file_bytes.unwrap();
	file_bytes.append(&mut time);
	file_bytes.append(&mut read_time_placeholder);
	file_bytes.append(&mut referrer);
	file_bytes.append(&mut body.to_vec());
	let msg_file = File::create(msg_path).await;
	if msg_file.is_err() { return_server_error!(); }
	let mut msg_file = msg_file.unwrap();
	
	if msg_file.lock_exclusive().is_err() { return_server_error!(); }
	
	if msg_file.write_all(&file_bytes).await.is_err() || msg_file.flush().await.is_err() {
		msg_file.unlock().ok();
		return_server_error!();
	}
	
	if msg_file.unlock().is_err() { return_server_error!(); }
	
	// add message to subscriptions if there are any
	if let Some(sub_list_lock) = listener_cache.get(&req.id).await {
		let sub_list: Listener;
		{ // leave the original Listener locked for the shortest possible time
			let sub_list_lock = sub_list_lock.read().unwrap();
			sub_list = (*sub_list_lock).clone();
		}
		for subscription_id in &sub_list.subscriptions {
			if let Some(subscription) = subscription_cache.get(subscription_id).await {
				let mut subscription = subscription.write().unwrap();
				if u32::try_from(subscription.messages.len()).is_err() { continue; } // skip any subscriptions that are already filled up
				subscription.messages.push(MessageInfo{
					id: String::from(&req.id),
					message_number: msg_number
				});
			}
		}
	}
	
	return HttpResponse::NoContent().insert_header(("X-MessageNumber", msg_number.to_string())).finish();
}



// delete a message
#[delete("/del/{id}/{msg_number}")]
async fn del(req: web::Path<DeleteMessageRequestScheme>, query: web::Query<MDCQuery>) -> impl Responder {
	// check if id is hex-string
	if !IS_HEX.is_match(&req.id) { return_client_error!("invalid id"); }
	// check if message detail code is valid
	if !IS_MDC.is_match(&query.mdc) { return_client_error!("invalid mdc"); }
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push(&req.id);
	path.push(&req.msg_number.to_string());
	if !path.is_file() { return_client_error!("message does not exist"); }
	let message_file = OpenOptions::new().read(true).write(true).truncate(true).open(&path).await;
	
	if message_file.is_err() { return_server_error!(); }
	let mut message_file = message_file.unwrap();
	
	if message_file.lock_exclusive().is_err() { return_server_error!(); }
	
	let mut file_bytes = [0u8;1usize+SAVED_MSG_MINIMUM].to_vec();
	if message_file.read_exact(&mut file_bytes).await.is_err() {
		message_file.unlock().ok();
		return_server_error!();
	}
	
	if file_bytes.len() <= SAVED_MSG_MINIMUM {
		if message_file.unlock().is_err() { return_server_error!(); }
		if file_bytes == DELETED.to_vec() {
			// message got deleted
			return HttpResponse::NoContent().insert_header(("X-Deleted", "true")).finish();
		}
		return_server_error!();
	}
	
	let (mdc, _) = file_bytes.split_at(4);
	
	if query.mdc == encode(mdc) {
		if message_file.write_all(&DELETED).await.is_err() || message_file.flush().await.is_err() {
			message_file.unlock().ok();
			return_server_error!();
		}
		if message_file.unlock().is_err() { return_server_error!(); }
		return_zero!();
	}
	else {
		if message_file.unlock().is_err() { return_server_error!(); }
		return_client_error!("wrong mdc");
	}
}

// subscribe to multiple IDs to request all their messages in one request
#[post("/subscribe")]
async fn subscribe(mut payload: web::Payload, subscription_cache: web::Data<Cache<u128, Arc<RwLock<Subscription>>>>, listener_cache: web::Data<Cache<String, Arc<RwLock<Listener>>>>) -> impl Responder {
	let mut body = web::BytesMut::new();
	while let Some(chunk) = payload.next().await {
		if chunk.is_err() {
			return_client_error!("network error");
		};
		let chunk = chunk.unwrap();
		if (body.len() + chunk.len()) > MAX_SND_SIZE {
			return_client_error!("request body over max upload size");
		}
		body.extend_from_slice(&chunk);
	}
	
	let body_text = String::from_utf8(body.to_vec());
	if body_text.is_err() {
		return_client_error!("body is not valid utf-8");
	}
	let body_text = body_text.unwrap();
	
	let id_split = body_text.split('\n').collect::<Vec<&str>>();
	if id_split.len() > 100 {
		return_client_error!("A subscription may only contain up to 100 IDs");
	}
	let subscription = Arc::new(
		RwLock::new(
			Subscription {
				messages: Vec::new(),
				mdc_map: HashMap::new()
			}
		)
	);
	
	let mut subscription_id = None;
	for _ in 1..20 {
		let id: u128 = rand::random();
		if !subscription_cache.contains_key(&id) {
			subscription_cache.insert(id, subscription.clone()).await;
			subscription_id = Some(id);
			break;
		}
	}
	if subscription_id.is_none() { return_server_error!(); }
	let subscription_id = subscription_id.unwrap();
	
	// since we are creating the subscription and don't use it anywhere else before its creation sequence is finished, this lock can be held without performance implications
	let mut sub = subscription.write().unwrap();
	
	for id_line in id_split {
		let mut id_info = id_line.split(' ');
		let id = id_info.next().unwrap();
		if id.is_empty() {
			continue;
		}
		let mdc = match id_info.next() {
			Some(mdc) => mdc,
			None => {
				return_client_error!("one or more IDs did not have an MDC associated with them");
			}
		};
		let start_msg_id = match id_info.next() {
			Some(start_msg_id) => start_msg_id.parse::<u16>().unwrap_or(0u16),
			None => 0u16
		};
		
		if !IS_HEX.is_match(id) {
			return_client_error!("body contains an invalid ID");
		}
		
		if !IS_MDC.is_match(mdc) {
			return_client_error!("one or more IDs did have an incorrectly formatted MDC associated with them");
		}
		
		sub.mdc_map.insert(id.to_string(), decode(mdc).unwrap());
		
		let mut id_path = PathBuf::from(RUNTIME_DIR);
		id_path.push(id);
		id_path.push("msg_number");
		if id_path.is_file() {
			// There are already messages present for this ID. Add all messages between the requested start message and the latest message to the subscription
			let msg_number_file = File::open(&id_path).await;
			if msg_number_file.is_err() { return_server_error!(); }
			let mut msg_number_file = msg_number_file.unwrap();
			if msg_number_file.lock_shared().is_err() { return_server_error!(); }
			let mut number_bytes = vec![];
			if msg_number_file.read_to_end(&mut number_bytes).await.is_err() {
				msg_number_file.unlock().ok();
				return_server_error!();
			}
			
			let msg_number = String::from_utf8_lossy(&number_bytes).into_owned().parse().unwrap_or(0);
			if msg_number >= start_msg_id {
				for i in start_msg_id..msg_number+1 {
					if u32::try_from(sub.messages.len()).is_err() { break; } // do not add messages if the subscription is already filled up
					sub.messages.push(
						MessageInfo {
							id: id.to_string(),
							message_number: i
						}
					);
				}
			}
		}
		
		let mut fresh = false;
		let listener = listener_cache.get_with(id.to_string(), async {
			fresh = true;
			Arc::new(
				RwLock::new(
					Listener {
						subscriptions: vec![subscription_id]
					}
				)
			)
		}).await;
		if !fresh {
			let mut listener = listener.write().unwrap();
			listener.subscriptions.push(subscription_id);
			// listener gets unlocked here
		}
	}
	let subscription_id = subscription_id.to_string().as_bytes().to_vec();
	HttpResponse::Ok().body(subscription_id)
}

// return all messages associated with a subscription after sub_msg_number
#[get("/sub/{subscription_id}/{sub_msg_number}")]
async fn get_subscription(req: web::Path<SubscriptionRequestScheme>, subscription_cache: web::Data<Cache<u128, Arc<RwLock<Subscription>>>>) -> impl Responder {
	let req_sub_id: u128 = match &req.subscription_id.parse() {
		Ok(res) => *res,
		Err(_) => { return_client_error!("invalid subscription ID"); }
	};
	let subscription_lock = match subscription_cache.get(&req_sub_id).await {
		Some(sub) => sub,
		None => { return_client_error!("subscription not found"); }
	};
	let subscription: Subscription;
	{
		let subscription_lock = subscription_lock.read().unwrap();
		subscription = (*subscription_lock).clone();
	}
	let saved_msg_number = u32::try_from(subscription.messages.len());
	if saved_msg_number.is_err() { return_server_error!(); }
	let saved_msg_number = saved_msg_number.unwrap();
	if saved_msg_number < req.sub_msg_number {
		return HttpResponse::NoContent().finish();
	}
	
	let mut response_struct = Messages {
		messages: Vec::<SubscriptionMessage>::new()
	};
	for sub_msg_number in req.sub_msg_number..saved_msg_number {
		let message_info = &subscription.messages[usize::try_from(sub_msg_number).unwrap()];
		let id = &message_info.id;
		let msg_number = &message_info.message_number;
		let sub_mdc = &subscription.mdc_map.get(id);
		if sub_mdc.is_none() { return_server_error!(); }
		let message = get_msg_validated(id, msg_number, sub_mdc.unwrap()).await;
		if message.is_none() { continue; }
		let message = message.unwrap();
		match message {
			Ok(res) => { response_struct.messages.push(SubscriptionMessage {
				status: "ok".to_string(),
				message: Some(
					MessageData {
						id: id.to_string(),
						msg_number: *msg_number,
						sent: res.sent,
						read: res.read,
						content: BASE64.encode(res.content)
					}
				)
			}); }
			Err(GetMessageError::InvalidInput) => { response_struct.messages.push(SubscriptionMessage {
				status: "invalid input".to_string(),
				message: None
			}); }
			Err(GetMessageError::WrongMdc) => { response_struct.messages.push(SubscriptionMessage {
				status: "wrong mdc".to_string(),
				message: None
			}); }
			Err(GetMessageError::Deleted) => { response_struct.messages.push(SubscriptionMessage {
				status: "deleted".to_string(),
				message: None
			}); }
			Err(GetMessageError::Other) => { response_struct.messages.push(SubscriptionMessage {
				status: "internal error".to_string(),
				message: None
			}); }
		};
	}
	let response_text = match serde_json::to_string(&response_struct) {
		Ok(res) => res,
		Err(_) => { return_server_error!(); }
	};
	let response_bytes = response_text.as_bytes().to_vec();
	HttpResponse::Ok().body(response_bytes)
}

// return the current time to allow clients to compare their system time with this. This is not supposed to be accurate, but rather good enough for clients to calculate temporary IDs
#[get("/time")]
async fn get_time() -> impl Responder {
	let time = Utc::now().timestamp().to_string();
	HttpResponse::Ok().content_type("text/plain").body(time)
}

// just return that this is in fact a Dawn server and an API version (used for URL checking in clients)
#[get("/dawn")]
async fn dawn() -> impl Responder {
	let response = "dawn:0.0.2\n".as_bytes();
	HttpResponse::Ok().content_type("text/plain").body(response)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	let subscription_cache = Cache::<u128, Arc<RwLock<Subscription>>>::builder().time_to_live(Duration::from_secs(4 * 60 * 60)).build();
	let listener_cache = Cache::<String, Arc<RwLock<Listener>>>::builder().time_to_live(Duration::from_secs(4 * 60 * 60)).build();
	let id_lock_cache = Cache::<String, Arc<RwLock<IdLock>>>::builder().build();
	let handle_lock_cache = Cache::<String, Arc<RwLock<HandleLock>>>::builder().build();
	let oti_lock_cache = Cache::<[u8; 32], Arc<RwLock<OtiLock>>>::builder().build();
	HttpServer::new(move || {
		App::new()
			.app_data(web::Data::new(subscription_cache.clone()))
			.app_data(web::Data::new(listener_cache.clone()))
			.app_data(web::Data::new(id_lock_cache.clone()))
			.app_data(web::Data::new(handle_lock_cache.clone()))
			.app_data(web::Data::new(oti_lock_cache.clone()))
			.service(rcv)
			.service(d)
			.service(read)
			.service(snd)
			.service(sethandle)
			.service(addkey)
			.service(handle_state)
			.service(gen_oti)
			.service(who)
			.service(del)
			.service(delhandle)
			.service(subscribe)
			.service(get_subscription)
			.service(get_time)
			.service(dawn)
	})
	.bind((SERVER_ADDRESS, SERVER_PORT))?
	.run()
	.await
}
