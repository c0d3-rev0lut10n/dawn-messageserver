/*	Copyright (c) 2023 Laurenz Werner
	
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

use crate::*;
use crate::response_schemes::*;
use actix_web::{get, post, delete, web, HttpResponse, Responder};
use std::path::PathBuf;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use hex::{encode, decode};
use futures::StreamExt;
use fs4::tokio::AsyncFileExt;

// set a handle for id called handle, or change it if it exists and correct password is provided via query string
// the client can also control how init requests are handled: when allow_public_init is seet to false, only clients which know the init_secret can get the information via /who
#[get("/sethandle/{id}/{handle}")]
pub async fn sethandle(req: web::Path<SetHandleRequestScheme>, query: web::Query<HandleEditQuery>) -> impl Responder {
	
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
	
	if handle_file.write_all(&file_content).await.is_err() || handle_file.flush().await.is_err() {
		handle_file.unlock().ok();
		return_server_error!();
	}
	if handle_file.unlock().is_err() { return_server_error!(); }
	
	return_zero!();
}

// add a key to a handle
#[post("/addkey/{handle}")]
pub async fn addkey(req: web::Path<AddKeyRequestScheme>, query: web::Query<HandlePasswordQuery>, mut payload: web::Payload) -> impl Responder {
	
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

// get information about current handle status
#[get("/handle_state/{handle}")]
pub async fn handle_state(req: web::Path<HandleStateRequestScheme>, query: web::Query<HandlePasswordQuery>) -> impl Responder {
	// check if handle has correct syntax
	if !IS_HANDLE.is_match(&req.handle) { return_client_error!("invalid handle"); }
	
	// check if query string is not empty
	if query.password.is_empty() { return_client_error!("no password provided"); }
	
	// get handle path, planned to use database in a later version
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push("handle");
	path.push(&req.handle);
	
	if !path.exists() { return_client_error!("handle not found"); }
	
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
	
	let mut handle_state_info = HandleState {
		key_slot_hashes: vec![],
	};
	
	for i in 0..key_number {
		path.pop();
		path.push(i.to_string());
		
		let key_file = File::open(&path).await;
		if key_file.is_err() { return_server_error!(); }
		let mut key_file = key_file.unwrap();
		
		let mut file_bytes = vec![];
		if key_file.read_to_end(&mut file_bytes).await.is_err() { return_server_error!(); }
		let hash = openssl::sha::sha256(&file_bytes);
		handle_state_info.key_slot_hashes.push(encode(hash));
	}
	
	if key_number_file.unlock().is_err() { return_server_error!(); }
	return HttpResponse::Ok().body(serde_json::to_string(&handle_state_info).unwrap());
}

// search for a handle
#[get("/who/{handle}")]
pub async fn who(req: web::Path<FindHandleRequestScheme>, query: web::Query<HandleInfoQuery>) -> impl Responder {
	// check if handle has correct syntax
	if !IS_HANDLE.is_match(&req.handle) { return_client_error!("invalid handle"); }
	
	// check if the init secret even matches the standard
	if !IS_INIT_SECRET.is_match(&query.init_secret) && !&query.init_secret.is_empty() { return_client_error!("invalid init_secret"); }
	
	// get handle path, planned to use database in a later version
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push("handle");
	path.push(&req.handle);
	if !path.exists() {
		return_zero!();
	}
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
	
	if file_content.len() != 81 { return_server_error!(); }
	
	let (_, handle_content) = file_content.split_at(32);
	let (handle_name, handle_data) = handle_content.split_at(32);
	let (allow_public_init, init_secret) = handle_data.split_at(1);
	
	// verify if init is allowed
	if allow_public_init[0] != 1u8 && query.init_secret.as_bytes() != init_secret {
		return_client_error!("init not allowed");
	}
	
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
	let key_number = key_number - 1;
	
	let truncate_number_file = OpenOptions::new().write(true).truncate(true).open(&path).await;
	if truncate_number_file.is_err() || truncate_number_file.unwrap().write_all((key_number).to_string().as_bytes()).await.is_err() || key_number_file.flush().await.is_err() {
		key_number_file.unlock().ok();
		return_server_error!();
	}
	
	if key_number_file.unlock().is_err() { return_server_error!(); }
	
	// get the next available key
	path.pop();
	path.push(key_number.to_string());
	
	let key_file = File::open(&path).await;
	if key_file.is_err() { return_server_error!(); }
	let mut key_file = key_file.unwrap();
	
	let mut file_bytes = vec![];
	if key_file.read_to_end(&mut file_bytes).await.is_err() { return_server_error!(); }
	
	if fs::remove_file(&path).await.is_err() { return_server_error!(); }
	
	let handle_name_string = encode(handle_name);
	return HttpResponse::Ok().insert_header(("X-ID", handle_name_string)).body(file_bytes);
}

// delete a handle
#[delete("/delhandle/{handle}")]
pub async fn delhandle(req: web::Path<DeleteHandleRequestScheme>, query: web::Query<HandlePasswordQuery>) -> impl Responder {
	// check if handle has correct syntax
	if !IS_HANDLE.is_match(&req.handle) { return_client_error!("invalid handle"); }
	// get handle path, planned to use database in a later version
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push("handle");
	path.push(&req.handle);
	
	if !path.exists() { return_client_error!("handle not found"); }
	
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
