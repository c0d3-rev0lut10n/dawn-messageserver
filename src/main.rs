#[macro_use]
extern crate lazy_static;

use actix_web::{get, post, delete, web, App, HttpResponse, HttpServer, Responder};
use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use regex::Regex;
use hex::{encode, decode};
use serde::Deserialize;
use futures::StreamExt;
use chrono::prelude::*;
use std::array::TryFromSliceError;

// constants, planned to be read from config file in a later version
const RUNTIME_DIR : &str = "./runtime";
const SERVER_ADDRESS : &str = "127.0.0.1";
const SERVER_PORT : u16 = 8080;
const MAX_SND_SIZE : usize = 256_000;
const SAVED_MSG_MINIMUM: usize = 12;

lazy_static! {
	// globally defined regex patterns
	static ref IS_HEX: Regex = Regex::new("^[0-9a-f]+$").unwrap();
	static ref IS_HANDLE: Regex = Regex::new("^[0-9a-zA-Z_-]+$").unwrap();
	static ref IS_MDC: Regex = Regex::new("^[0-9a-f]{8}$").unwrap();
	// pattern for deleted messages
	static ref DELETED : Vec<u8> = vec![255];

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
		/*let mut response = vec![1];
		response.append(&mut $a);
		return HttpResponse::Ok().content_type("application/octet-stream").body(response)*/
		return HttpResponse::Ok().content_type("application/octet-stream").body($a)
	}
}

// zero return macro
macro_rules! return_zero {
	() => {
		//return HttpResponse::Ok().content_type("application/octet-stream").body(vec![0])
		return HttpResponse::NoContent().finish()
	}
}

#[derive(Deserialize)]
struct ReceiveRequestScheme {
	id : String,
	msg_number : u16,
}

#[derive(Deserialize)]
struct SendRequestScheme {
	id : String,
}

#[derive(Deserialize)]
struct MDCQuery {
	mdc : String,
}

#[derive(Deserialize)]
struct SetHandleRequestScheme {
	id : String,
	handle : String,
}

#[derive(Deserialize)]
struct HandlePasswordQuery {
	password : String,
}

#[derive(Deserialize)]
struct FindHandleRequestScheme {
	handle : String,
}

#[derive(Deserialize)]
struct DeleteMessageRequestScheme {
	id : String,
	msg_number : u16,
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
	let mut path = Path::new(RUNTIME_DIR).to_owned();
	path.push(&req.id);
	path.push(&req.msg_number.to_string());
	if !path.is_file() {
		// message does not exist
		return_zero!();
	}
	// message does exist
	let file_content = fs::read(&path);
	if file_content.is_err() { return_server_error!(); }
	let file_bytes = file_content.unwrap();
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
	let mut path = Path::new(RUNTIME_DIR).to_owned();
	path.push(&req.id);
	path.push(&req.msg_number.to_string());
	if !path.is_file() {
		// message does not exist
		return_zero!();
	}
	// message does exist
	let file_content = fs::read(&path);
	if file_content.is_err() { return_server_error!(); }
	let file_bytes = file_content.unwrap();
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
	if query.mdc != encode(&mdc) {
		return_client_error!("wrong mdc");
	}
	let (timestamp_bytes, _) = info.split_at(8);
	let timestamp_slice : Result<[u8;8], TryFromSliceError> = timestamp_bytes.to_owned().as_slice().try_into();
	if timestamp_slice.is_err() { return_server_error!(); }
	let timestamp = i64::from_le_bytes(timestamp_slice.unwrap());
	return HttpResponse::NoContent().insert_header(("X-Timestamp", timestamp.to_string())).finish();
	//return HttpResponse::NotImplemented().finish();
}

// send message to id with message detail code in query string and content in body
#[post("/snd/{id}")]
async fn snd(req: web::Path<SendRequestScheme>, query: web::Query<MDCQuery>, mut payload : web::Payload) -> impl Responder {
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
	if body.len() == 0 { return_client_error!("empty body"); }
	// check if id is hex-string
	if !IS_HEX.is_match(&req.id) { return_client_error!("invalid id"); }
	// check if mdc in query string is valid
	if !IS_MDC.is_match(&query.mdc) { return_client_error!("invalid message detail code"); }
	// get current time
	let mut time = Utc::now().timestamp().to_le_bytes().to_vec();
	// get file path, planned to use database in a later version
	let mut path = Path::new(RUNTIME_DIR).to_owned();
	path.push(&req.id);
	if !path.exists() {
		// first message for id, therefore create directory
		if fs::create_dir(path).is_err() { return_server_error!(); }
		// save number of messages to file
		let mut msg_number_file = Path::new(RUNTIME_DIR).to_owned();
		msg_number_file.push(&req.id.to_string());
		msg_number_file.push("msg_number");
		let number_file = File::create(msg_number_file);
		if number_file.is_err() { return_server_error!(); }
		if number_file.unwrap().write_all("0".as_bytes()).is_err() { return_server_error!(); }
		let mut msg_path = Path::new(RUNTIME_DIR).to_owned();
		msg_path.push(&req.id.to_string());
		msg_path.push("0");
		// write content and mdc to file
		let file_bytes = decode(&query.mdc);
		if file_bytes.is_err() { return_client_error!("invalid message detail code"); }
		else {
			let mut file_bytes = file_bytes.unwrap();
			file_bytes.append(&mut time);
			file_bytes.append(&mut body.to_vec());
			let mut msg_file = File::create(msg_path).expect("File creation error");
			if msg_file.write_all(&file_bytes).is_err() { return_server_error!(); }
			if msg_file.flush().is_err() { return_server_error!(); }
		}
	}
	else {
		// there are already messages for this id
		let mut msg_number_file = Path::new(RUNTIME_DIR).to_owned();
		msg_number_file.push(&req.id.to_string());
		msg_number_file.push("msg_number");
		let msg_number = String::from_utf8_lossy(&fs::read(&msg_number_file).expect("File reading error")).to_owned().parse().unwrap_or(0) + 1;
		if msg_number > 60000 { return_client_error!("Too many messages"); }
		let mut number_file = OpenOptions::new().write(true).truncate(true).open(&msg_number_file).expect("File writing error");
		if number_file.write_all(&msg_number.to_string().as_bytes()).is_err() { return_server_error!(); }
		if number_file.flush().is_err() { return_server_error!(); }
		let mut msg_path = Path::new(RUNTIME_DIR).to_owned();
		msg_path.push(&req.id.to_string());
		msg_path.push(&msg_number.to_string());
		// write content and mdc to file
		let file_bytes = decode(&query.mdc);
		if file_bytes.is_err() { return_client_error!("Invalid message detail code"); }
		else {
			let mut file_bytes = file_bytes.unwrap();
			file_bytes.append(&mut time);
			file_bytes.append(&mut body.to_vec());
			let mut msg_file = File::create(msg_path).expect("File creation error");
			if msg_file.write_all(&file_bytes).is_err() { return_server_error!(); }
			if msg_file.flush().is_err() { return_server_error!(); }
		}
	}
	return_zero!();
}

// set a handle for id called handle, or change it if it exists and correct password is provided via query string
#[post("/sethandle/{id}/{handle}")]
async fn sethandle(req: web::Path<SetHandleRequestScheme>, query: web::Query<HandlePasswordQuery>, mut payload : web::Payload) -> impl Responder {
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
	if body.len() == 0 {
		return_client_error!("empty body");
	}
	// check if id is sucessfully decodable to bytes and has the right size
	if !IS_HEX.is_match(&req.id) { return_client_error!("invalid id"); }
	let id_decode = decode(&req.id);
	if id_decode.is_err() { return_client_error!("invalid id"); }
	let id_bytes = id_decode.unwrap();
	if id_bytes.len() != 32 { return_client_error!("invalid id length"); }
	// check if query string is not empty
	if &query.password == "" { return_client_error!("no password provided"); }
	// check if handle has correct syntax
	if !IS_HANDLE.is_match(&req.handle) { return_client_error!("incorrect handle syntax"); }
	// get handle path, planned to use database in a later version
	let mut path = Path::new(RUNTIME_DIR).to_owned();
	path.push("handle");
	path.push(&req.handle);
	let password_hash = openssl::sha::sha256(&query.password.as_bytes());
	if !path.exists() {
		// handle is not used yet
		let mut file_content = vec![];
		file_content.append(&mut password_hash.to_vec());
		file_content.append(&mut id_bytes.to_vec());
		file_content.append(&mut body.to_vec());
		let mut handle_file = File::create(&path).expect("File creation error");
		if handle_file.write_all(&file_content).is_err() { return_server_error!(); }
		if handle_file.flush().is_err() { return_server_error!(); }
		return_bytes!(vec![]);
	}
	else {
		// handle is used, check if password matches
		let saved_content = fs::read(&path).expect("File reading error");
		let (saved_hash, _) = saved_content.split_at(32);
		// check if hash matches
		if password_hash != saved_hash { return_client_error!("wrong password"); }
		// write new content to file
		let handle_file_open = OpenOptions::new().write(true).truncate(true).open(&path);
		if handle_file_open.is_err() { return_server_error!(); }
		let mut handle_file = handle_file_open.unwrap();
		let mut file_content = vec![];
		file_content.append(&mut password_hash.to_vec());
		file_content.append(&mut id_bytes.to_vec());
		file_content.append(&mut body.to_vec());
		if handle_file.write_all(&file_content).is_err() { return_server_error!(); }
		if handle_file.flush().is_err() { return_server_error!(); }
		return_zero!();
	}
}

// search for a handle
#[get("/who/{handle}")]
async fn who(req: web::Path<FindHandleRequestScheme>) -> impl Responder {
	// check if handle has correct syntax
	if !IS_HANDLE.is_match(&req.handle) { return_client_error!("invalid handle"); }
	// get handle path, planned to use database in a later version
	let mut path = Path::new(RUNTIME_DIR).to_owned();
	path.push("handle");
	path.push(&req.handle);
	if path.exists() {
		// handle exists
		let file_content = fs::read(&path).expect("File reading error");
		if file_content.len() <= 64 { return_server_error!(); }
		let (_, handle_content) = file_content.split_at(32);
		let (handle_name, handle_data) = handle_content.split_at(32);
		let handle_name_string = encode(&handle_name);
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
	let mut path = Path::new(RUNTIME_DIR).to_owned();
	path.push("handle");
	path.push(&req.handle);
	if path.exists() {
		// verify password
		let password_hash = openssl::sha::sha256(&query.password.as_bytes());
		let saved_content = fs::read(&path);
		if saved_content.is_err() { return_server_error!(); }
		let saved_content = saved_content.unwrap();
		let (saved_hash, _) = saved_content.split_at(32);
		// check if hash matches
		if password_hash != saved_hash { return_client_error!("wrong password"); }
		// delete handle
		if fs::remove_file(&path).is_err() { return_server_error!(); }
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
	let mut path = Path::new(RUNTIME_DIR).to_owned();
	path.push(&req.id);
	path.push(&req.msg_number.to_string());
	if path.is_file() {
		let file_content = fs::read(&path);
		if file_content.is_err() { return_server_error!(); }
		let file_bytes = file_content.unwrap();
		if file_bytes.len() <= 4 {
			if file_bytes == DELETED.to_vec() {
				// message got deleted
				let response = vec![255];
				return HttpResponse::Ok().content_type("application/octet-stream").body(response);
			}
			return_server_error!();
		}
		let (mdc, _) = file_bytes.split_at(4);
		if query.mdc == encode(&mdc) {
			let file = OpenOptions::new().write(true).truncate(true).open(&path);
			if file.is_err() { return_server_error!(); }
			let mut file = file.unwrap();
			if file.write_all(&DELETED).is_err() { return_server_error!(); }
			if file.flush().is_err() { return_server_error!(); }
			return_zero!();
		}
		else { return_client_error!("wrong mdc"); }
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
			.service(who)
			.service(del)
			.service(delhandle)
	})
	.bind((SERVER_ADDRESS, SERVER_PORT))?
	.run()
	.await
}
