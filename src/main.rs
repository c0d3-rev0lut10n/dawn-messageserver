/*	Copyright (c) 2022, 2023 Laurenz Werner
	
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

use actix_web::{get, post, delete, web, App, HttpResponse, HttpServer, Responder};
use std::path::PathBuf;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use regex::Regex;
use hex::{encode, decode};
use serde::Deserialize;
use futures::StreamExt;
use chrono::prelude::*;
use std::array::TryFromSliceError;
use fs4::tokio::AsyncFileExt;

// constants, planned to be read from config file in a later version
const RUNTIME_DIR: &str = "./runtime";
const SERVER_ADDRESS: &str = "127.0.0.1";
const SERVER_PORT: u16 = 8080;
const MAX_SND_SIZE: usize = 256_000;
const SAVED_MSG_MINIMUM: usize = 12;

lazy_static! {
	// globally defined regex patterns
	static ref IS_HEX: Regex = Regex::new("^[0-9a-f]+$").unwrap();
	static ref IS_HANDLE: Regex = Regex::new("^[0-9a-zA-Z_-]+$").unwrap();
	static ref IS_MDC: Regex = Regex::new("^[0-9a-f]{8}$").unwrap();
	static ref IS_INIT_SECRET: Regex = Regex::new("^[0-9a-zA-Z]{16}$").unwrap();
	// pattern for deleted messages
	static ref DELETED: Vec<u8> = vec![255];

}

// server error return macro
macro_rules! return_server_error {
	() => {
		return HttpResponse::InternalServerError().content_type("text/plain").body("Internal server error")
	}
}

// client error return macro
macro_rules! return_client_error {
	($a:expr) => {
		return HttpResponse::BadRequest().content_type("text/plain").body($a)
	}
}

// byte return macro
macro_rules! return_bytes {
	($a:expr) => {
		return HttpResponse::Ok().content_type("application/octet-stream").body($a)
	}
}

// zero return macro
macro_rules! return_zero {
	() => {
		return HttpResponse::NoContent().finish()
	}
}

#[derive(Deserialize)]
struct ReceiveRequestScheme {
	id: String,
	msg_number: u16,
}

#[derive(Deserialize)]
struct SendRequestScheme {
	id: String,
}

#[derive(Deserialize)]
struct MDCQuery {
	mdc: String,
}

#[derive(Deserialize)]
struct SetHandleRequestScheme {
	id: String,
	handle: String,
}

#[derive(Deserialize)]
struct AddKeyRequestScheme {
	handle: String,
}

#[derive(Deserialize)]
struct HandlePasswordQuery {
	password: String,
}

#[derive(Deserialize)]
struct HandleEditQuery {
	password: String,
	allow_public_init: bool,
	init_secret: String
}

#[derive(Deserialize)]
struct HandleInfoQuery {
	init_secret: String
}

#[derive(Deserialize)]
struct FindHandleRequestScheme {
	handle: String,
}

#[derive(Deserialize)]
struct DeleteMessageRequestScheme {
	id: String,
	msg_number: u16,
}

#[derive(Deserialize)]
struct DeleteHandleRequestScheme {
	handle: String,
}

// receive specified message
#[get("/rcv/{id}/{msg_number}")]
async fn rcv(req: web::Path<ReceiveRequestScheme>) -> impl Responder {
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
			let response = vec![255];
			return HttpResponse::Ok().content_type("application/octet-stream").body(response);
		}
		return_server_error!();
	}
	let (_, message) = file_bytes.split_at(12);
	
	return_bytes!(message.to_vec());
}

// get details for a message, currently only the timestamp
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
			let response = vec![255];
			return HttpResponse::Ok().content_type("application/octet-stream").body(response);
		}
		return_server_error!();
	}
	let (mdc, info) = file_bytes.split_at(4);
	
	// verify mdc
	if query.mdc != encode(mdc) {
		return_client_error!("wrong mdc");
	}
	
	let (timestamp_bytes, _) = info.split_at(8);
	let timestamp_slice: Result<[u8;8], TryFromSliceError> = timestamp_bytes.to_owned().as_slice().try_into();
	if timestamp_slice.is_err() { return_server_error!(); }
	let timestamp = i64::from_le_bytes(timestamp_slice.unwrap());
	
	return HttpResponse::NoContent().insert_header(("X-Timestamp", timestamp.to_string())).finish();
}

// send message to id with message detail code in query string and content in body
#[post("/snd/{id}")]
async fn snd(req: web::Path<SendRequestScheme>, query: web::Query<MDCQuery>, mut payload: web::Payload) -> impl Responder {
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
	// get current time
	let mut time = Utc::now().timestamp().to_le_bytes().to_vec();
	
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
		let mut msg_number_file = PathBuf::from(RUNTIME_DIR);
		msg_number_file.push(&req.id);
		msg_number_file.push("msg_number");
		let number_file = File::create(msg_number_file).await;
		if number_file.is_err() { return_server_error!(); }
		let mut number_file = number_file.unwrap();
		
		if number_file.lock_exclusive().is_err() { return_server_error!(); }
		
		if number_file.write_all("0".as_bytes()).await.is_err() {
			number_file.unlock().ok();
			return_server_error!();
		}
		
		if number_file.unlock().is_err() { return_server_error!(); }
		
		let mut msg_path = PathBuf::from(RUNTIME_DIR);
		msg_path.push(&req.id);
		msg_path.push("0");
		// write content and mdc to file
		let file_bytes = decode(&query.mdc);
		if file_bytes.is_err() { return_client_error!("invalid message detail code"); }
		else {
			let mut file_bytes = file_bytes.unwrap();
			file_bytes.append(&mut time);
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
		}
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
		
		let mut msg_path = PathBuf::from(RUNTIME_DIR);
		msg_path.push(&req.id);
		msg_path.push(&msg_number.to_string());
		
		// write content and mdc to file
		let file_bytes = decode(&query.mdc);
		if file_bytes.is_err() { return_client_error!("Invalid message detail code"); }
		let mut file_bytes = file_bytes.unwrap();
		file_bytes.append(&mut time);
		file_bytes.append(&mut body.to_vec());
		let mut msg_file = File::create(msg_path).await.expect("File creation error");
		
		if msg_file.lock_exclusive().is_err() { return_server_error!(); }
					
		if msg_file.write_all(&file_bytes).await.is_err() || msg_file.flush().await.is_err() {
			msg_file.unlock().ok();
			return_server_error!();
		}
		
		if msg_file.unlock().is_err() { return_server_error!(); }
	}
	return HttpResponse::NoContent().insert_header(("X-MessageNumber", msg_number.to_string())).finish();
}

// set a handle for id called handle, or change it if it exists and correct password is provided via query string
// the client can also control how init requests are handled: when allow_public_init is seet to false, only clients which know the init_secret can get the information via /who
#[post("/sethandle/{id}/{handle}")]
async fn sethandle(req: web::Path<SetHandleRequestScheme>, query: web::Query<HandleEditQuery>, mut payload: web::Payload) -> impl Responder {
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
	if body.is_empty() {
		return_client_error!("empty body");
	}
	// check if id is sucessfully decodable to bytes and has the right size
	if !IS_HEX.is_match(&req.id) { return_client_error!("invalid id"); }
	let id_decode = decode(&req.id);
	if id_decode.is_err() { return_client_error!("invalid id"); }
	let id_bytes = id_decode.unwrap();
	if id_bytes.len() != 32 { return_client_error!("invalid id length"); }
	// check if query string is not empty
	if query.password.is_empty() { return_client_error!("no password provided"); }
	// check if handle has correct syntax
	if !IS_HANDLE.is_match(&req.handle) { return_client_error!("incorrect handle syntax"); }
	
	// check if init_secret is valid
	if !IS_INIT_SECRET.is_match(&query.init_secret) { return_client_error!("init secret invalid"); }
	
	// get allow_public_init
	let allow_public_init = match query.allow_public_init {
		true => 1u8,
		false => 0u8
	};
	
	// get handle path, planned to use database in a later version
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push("handle");
	path.push(&req.handle);
	let password_hash = openssl::sha::sha256(query.password.as_bytes());
	
	// check if handle exists
	let handle_already_taken = path.exists();
	
	let open_handle_file;
	let mut handle_file;
	
	// check password if the handle is taken
	if handle_already_taken {
		// handle is used, check if password matches
		open_handle_file = OpenOptions::new().read(true).open(&path).await;
		if open_handle_file.is_err() { return_server_error!(); }
		handle_file = open_handle_file.unwrap();
		
		if handle_file.lock_exclusive().is_err() { return_server_error!(); }
		
		let mut saved_content = vec![];
		if handle_file.read_to_end(&mut saved_content).await.is_err() {
			handle_file.unlock().ok();
			return_server_error!();
		}
		
		let (saved_hash, _) = saved_content.split_at(32);
		// check if hash matches
		if password_hash != saved_hash {
			if handle_file.unlock().is_err() { return_server_error!(); }
			return_client_error!("wrong password");
		}
		
		// open file for overwriting
		let handle_file_writable = OpenOptions::new().write(true).truncate(true).open(&path).await;
		if handle_file_writable.is_err() { return_server_error!(); }
		handle_file = handle_file_writable.unwrap();
	}
	else {
		open_handle_file = File::create(&path).await;
		if open_handle_file.is_err() { return_server_error!(); }
		handle_file = open_handle_file.unwrap();
		
		if handle_file.lock_exclusive().is_err() { return_server_error!(); }
		
		// create a directory to allow storing keys
		path.pop();
		path.push(&(String::from(&req.handle) + ".keys"));
		if fs::create_dir(&path).await.is_err() { return_server_error!(); }
		
		// create the key_number file
		path.push("key_number");
		let key_number_file = File::create(&path).await;
		if key_number_file.is_err() { return_server_error!(); }
		let mut key_number_file = key_number_file.unwrap();
		
		if key_number_file.lock_exclusive().is_err() { return_server_error!(); }
		
		if key_number_file.write_all("0".as_bytes()).await.is_err() {
			key_number_file.unlock().ok();
			return_server_error!();
		}
		
		if key_number_file.unlock().is_err() { return_server_error!(); }
	}
	
	// write content to file
	let mut file_content = vec![];
	file_content.append(&mut password_hash.to_vec());
	file_content.append(&mut id_bytes.to_vec());
	file_content.append(&mut vec![allow_public_init]);
	file_content.append(&mut query.init_secret.as_bytes().to_vec());
	file_content.append(&mut body.to_vec());
	if handle_file.write_all(&file_content).await.is_err() || handle_file.flush().await.is_err() {
		handle_file.unlock().ok();
		return_server_error!();
	}
	if handle_file.unlock().is_err() { return_server_error!(); }
	
	return_zero!();
}

// add a key to a handle
// UNDER DEVELOPMENT
#[post("/addkey/{handle}")]
async fn addkey(req: web::Path<AddKeyRequestScheme>, query: web::Query<HandlePasswordQuery>, mut payload: web::Payload) -> impl Responder {
	
	// check if handle has correct syntax
	if !IS_HANDLE.is_match(&req.handle) { return_client_error!("invalid handle"); }
	
	// check if query string is not empty
	if query.password.is_empty() { return_client_error!("no password provided"); }
	
	// get handle path, planned to use database in a later version
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push("handle");
	path.push(&req.handle);
	
	if !path.exists() { return_client_error!("handle not found"); }
	
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
	if body.is_empty() {
		return_client_error!("empty body");
	}
	
	let password_hash = openssl::sha::sha256(query.password.as_bytes());
	
	let open_handle_file = OpenOptions::new().read(true).open(&path).await;
	if open_handle_file.is_err() { return_server_error!(); }
	let mut handle_file = open_handle_file.unwrap();
	
	if handle_file.lock_shared().is_err() { return_server_error!(); }
	
	let mut saved_content = vec![];
	if handle_file.read_to_end(&mut saved_content).await.is_err() {
		handle_file.unlock().ok();
		return_server_error!();
	}
	
	let (saved_hash, _) = saved_content.split_at(32);
	// check if hash matches
	if password_hash != saved_hash {
		if handle_file.unlock().is_err() { return_server_error!(); }
		return_client_error!("wrong password");
	}
	
	path.pop();
	path.push(&(String::from(&req.handle) + ".keys"));
	path.push("key_number");
	
	// lock exclusively to prevent race conditions
	let key_number_file = OpenOptions::new().read(true).open(&path).await;
	if key_number_file.is_err() { return_server_error!(); }
	let mut key_number_file = key_number_file.unwrap();
	
	if key_number_file.lock_exclusive().is_err() { return_server_error!(); }
	
	let mut key_number_bytes = vec![];
	if key_number_file.read_to_end(&mut key_number_bytes).await.is_err() {
		key_number_file.unlock().ok();
		return_server_error!();
	}
	
	let key_number = String::from_utf8_lossy(&key_number_bytes).into_owned().parse().unwrap_or(0);
	
	if key_number > 15 {
		if key_number_file.unlock().is_err() { return_server_error!(); }
		return_client_error!("all key slots full");
	}
	
	let truncate_number_file = OpenOptions::new().write(true).truncate(true).open(&path).await;
	if truncate_number_file.is_err() || truncate_number_file.unwrap().write_all((key_number + 1).to_string().as_bytes()).await.is_err() || key_number_file.flush().await.is_err() {
		key_number_file.unlock().ok();
		return_server_error!();
	}
	
	if key_number_file.unlock().is_err() { return_server_error!(); }
	
	// save the key
	path.pop();
	path.push(key_number.to_string());
	let mut key_file = File::create(&path).await.expect("File creation error");
	
	if key_file.lock_exclusive().is_err() { return_server_error!(); }
				
	if key_file.write_all(&body).await.is_err() || key_file.flush().await.is_err() {
		key_file.unlock().ok();
		return_server_error!();
	}
	
	if key_file.unlock().is_err() { return_server_error!(); }
	
	return_zero!();
}

// search for a handle
#[get("/who/{handle}")]
async fn who(req: web::Path<FindHandleRequestScheme>, query: web::Query<HandleInfoQuery>) -> impl Responder {
	// check if handle has correct syntax
	if !IS_HANDLE.is_match(&req.handle) { return_client_error!("invalid handle"); }
	
	// check if the init secret even matches the standard
	if !IS_INIT_SECRET.is_match(&query.init_secret) { return_client_error!("invalid init_secret"); }
	
	// get handle path, planned to use database in a later version
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push("handle");
	path.push(&req.handle);
	if path.exists() {
		// handle exists
		let handle_file = File::open(&path).await;
		if handle_file.is_err() { return_server_error!(); }
		let mut handle_file = handle_file.unwrap();
		let mut file_content = vec![];
		
		if handle_file.lock_shared().is_err() { return_server_error!(); }
		
		if handle_file.read_to_end(&mut file_content).await.is_err() {
			handle_file.unlock().ok();
			return_server_error!();
		}
		
		if handle_file.unlock().is_err() { return_server_error!(); }
		
		if file_content.len() <= 81 { return_server_error!(); }
		
		let (_, handle_content) = file_content.split_at(32);
		let (handle_name, handle_data) = handle_content.split_at(32);
		let (allow_public_init, handle_data) = handle_data.split_at(1);
		let (init_secret, handle_data) = handle_data.split_at(16);
		
		// navigate to the key_number file
		path.pop();
		path.push(&(String::from(&req.handle) + ".keys"));
		path.push("key_number");
		
		// lock the file and get the current key number
		let key_number_file = OpenOptions::new().read(true).open(&path).await;
		if key_number_file.is_err() { return_server_error!(); }
		let mut key_number_file = key_number_file.unwrap();
		
		if key_number_file.lock_exclusive().is_err() { return_server_error!(); }
		
		let mut key_number_bytes = vec![];
		if key_number_file.read_to_end(&mut key_number_bytes).await.is_err() {
			key_number_file.unlock().ok();
			return_server_error!();
		}
		
		let key_number = String::from_utf8_lossy(&key_number_bytes).into_owned().parse().unwrap_or(0);
		
		if key_number < 1 {
			if key_number_file.unlock().is_err() { return_server_error!(); }
			return_client_error!("all key slots empty");
		}
		
		// get the next available key
		
		// verify if init is allowed
		if allow_public_init[0] != 1u8 && query.init_secret.as_bytes().to_vec() != init_secret {
			return_client_error!("init not allowed");
		}
		let handle_name_string = encode(handle_name);
		return HttpResponse::Ok().insert_header(("X-ID", handle_name_string)).body(handle_data.to_vec());
	}
	return_zero!();
}

// delete a handle
#[delete("/delhandle/{handle}")]
async fn delhandle(req: web::Path<DeleteHandleRequestScheme>, query: web::Query<HandlePasswordQuery>) -> impl Responder {
	// check if handle has correct syntax
	if !IS_HANDLE.is_match(&req.handle) { return_client_error!("invalid handle"); }
	// get handle path, planned to use database in a later version
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push("handle");
	path.push(&req.handle);
	if path.exists() {
		// verify password
		let password_hash = openssl::sha::sha256(query.password.as_bytes());
		
		let handle_file = File::open(&path).await;
		if handle_file.is_err() { return_server_error!(); }
		let mut handle_file = handle_file.unwrap();
		let mut saved_content = vec![];
		
		// Lock shared first to prevent a DOS attack on a handle that could result in the handle being unable to get read by who function
		if handle_file.lock_shared().is_err() { return_server_error!(); }
		
		if handle_file.read_to_end(&mut saved_content).await.is_err() {
			handle_file.unlock().ok();
			return_server_error!();
		}
		
		if handle_file.unlock().is_err() { return_server_error!(); }
		
		let (saved_hash, _) = saved_content.split_at(32);
		// check if hash matches
		if password_hash != saved_hash { return_client_error!("wrong password"); }
		// delete handle
		if handle_file.lock_exclusive().is_err() { return_server_error!(); }
		if fs::remove_file(&path).await.is_err() { return_server_error!(); }
		
		// delete keys directory
		path.pop();
		path.push(&(String::from(&req.handle) + ".keys"));
		
		if fs::remove_dir_all(path).await.is_err() { return_server_error!(); }
		
		if handle_file.unlock().is_err() { return_server_error!(); }
		return_zero!();
	}
	return_client_error!("handle not found");
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
	if path.is_file() {
		let message_file = OpenOptions::new().read(true).write(true).truncate(true).open(&path).await;
		
		if message_file.is_err() { return_server_error!(); }
		let mut message_file = message_file.unwrap();
		
		if message_file.lock_exclusive().is_err() { return_server_error!(); }
		
		let mut file_bytes = vec![];
		if message_file.read_to_end(&mut file_bytes).await.is_err() {
			message_file.unlock().ok();
			return_server_error!();
		}
		
		if file_bytes.len() <= SAVED_MSG_MINIMUM {
			if message_file.unlock().is_err() { return_server_error!(); }
			if file_bytes == DELETED.to_vec() {
				// message got deleted
				let response = vec![255];
				return HttpResponse::Ok().content_type("application/octet-stream").body(response);
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
	else {
		return_client_error!("message does not exist");
	}
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	HttpServer::new(|| {
		App::new()
			.service(rcv)
			.service(d)
			.service(snd)
			.service(sethandle)
			.service(addkey)
			.service(who)
			.service(del)
			.service(delhandle)
	})
	.bind((SERVER_ADDRESS, SERVER_PORT))?
	.run()
	.await
}
