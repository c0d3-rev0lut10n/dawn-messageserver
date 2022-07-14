#[macro_use]
extern crate lazy_static;

use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, Result};
use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use regex::Regex;
use hex::encode;
use serde::Deserialize;
use futures::StreamExt;

// constants, planned to be read from config file in a later version
const RUNTIME_DIR : &str = "./runtime";
const SERVER_ADDRESS : &str = "127.0.0.1";
const SERVER_PORT : u16 = 8080;
const MAX_SND_SIZE: usize = 262_144;

// globally defined regex patterns
lazy_static! {
	static ref IS_HEX: Regex = Regex::new("^[0-9a-f]+$").unwrap();
	static ref IS_ALPHANUMERIC: Regex = Regex::new("^[0-9a-zA-Z]+$").unwrap();
	static ref IS_MDC: Regex = Regex::new("^[0-9a-f]{8}$").unwrap();
}

// string return macro
macro_rules! return_string {
	($a:expr) => {
		//return Ok($a.to_string())
		return HttpResponse::Ok().content_type("text/plain").body($a)
	}
}

// error return macro
macro_rules! return_error {
	($a:expr) => {
		return HttpResponse::Ok().content_type("application/octet-stream").body(vec![9].append(&mut $a.as_bytes().to_vec()))
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
struct QueryString {
	s : String,
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().content_type("image/png").body([0u8;12].to_vec())
}

#[get("/rcv/{id}/{msg_number}")]
async fn rcv(req: web::Path<ReceiveRequestScheme>) -> impl Responder {
	// check if id is hex-string
	//if !&self.is_hex.is_match(&id) { return_string!("FAIL: parsing error"); }
	if !IS_HEX.is_match(&req.id) { return_string!("FAIL: parsing error"); }
	let mut path = Path::new(RUNTIME_DIR).to_owned();
	path.push(&req.id);
	path.push(&req.msg_number.to_string());
	if !path.is_file() {
		// message does not exist
		return HttpResponse::Ok().content_type("application/octet-stream").body(vec![0]);
	}
	// message does exist
	let mut response = "1".to_string();
	let file_content = fs::read(&path);
	if file_content.is_err() { return_error!("internal error"); }
	let file_bytes = file_content.unwrap();
	let contents = String::from_utf8_lossy(&file_bytes);
	// extract content, don't send mdc for obvious reasons
	let mut content_split = contents.split("\n");
	let message_ct = content_split.next();
	if message_ct.is_none() { return_error!("internal error"); }
	response = response + "\r\n" + &message_ct.unwrap();
	//Ok(response)
	HttpResponse::Ok().content_type("text/plain").body("it works!".to_owned() + &req.id + req.msg_number.to_string().as_str())
}

// send message to id with message deletion code in query string and content in body
#[post("/snd/{id}")]
//TODO: REFACTOR
async fn snd(req: web::Path<SendRequestScheme>, query: web::Query<QueryString>, mut payload : web::Payload) -> impl Responder {
	let mut body = web::BytesMut::new();
	while let Some(chunk) = payload.next().await {
		if chunk.is_err() {
			// error handling for network failures, return some kind of error message
		};
		let chunk = chunk.unwrap();
		if (body.len() + chunk.len()) > MAX_SND_SIZE {
			// body larger than maximum allowed size - add error handling!
		}
		body.extend_from_slice(&chunk);
	}
	// check if id is hex-string
	if !IS_HEX.is_match(&req.id) { return_error!("invalid id"); }
	// check if mdc in query string is valid
	if !IS_MDC.is_match(&query.s) { return_error!("invalid message deletion code"); }
	// get content
	let sent_content = String::from_utf8_lossy(&body);
	// check if content is hex-string
	if !IS_HEX.is_match(&sent_content) { return_error!("parsing error"); }
	// define variable for message number
	let mut msg_number : u16 = 1;
	// get file path, planned to use database in a later version
	let mut path = Path::new(RUNTIME_DIR).to_owned();
	path.push(&req.id);
	if !path.exists() {
		// first message for id, therefore create directory
		if fs::create_dir(path).is_err() { return_error!("internal error"); }
		// save number of messages to file
		let mut msg_number_file = Path::new(RUNTIME_DIR).to_owned();
		msg_number_file.push(&req.id.to_string());
		msg_number_file.push("msg_number");
		let mut number_file = File::create(msg_number_file).expect("File creation error");
		if number_file.write_all("1".as_bytes()).is_err() { return_error!("internal error"); }
		let mut msg_path = Path::new(RUNTIME_DIR).to_owned();
		msg_path.push(&req.id.to_string());
		msg_path.push("1");
		// write content and mdc to file
		let msg_file_content = sent_content.to_string() + "\r\n" + &query.s;
		let mut msg_file = File::create(msg_path).expect("File creation error");
		if msg_file.write_all(&msg_file_content.as_bytes()).is_err() { return_error!("internal error"); }
		if msg_file.flush().is_err() { return_error!("internal error"); }
	}
	else {
		// there are already messages for this id
		let mut msg_number_file = Path::new(RUNTIME_DIR).to_owned();
		msg_number_file.push(&req.id.to_string());
		msg_number_file.push("msg_number");
		msg_number = String::from_utf8_lossy(&fs::read(&msg_number_file).expect("File reading error")).to_owned().parse().unwrap_or(0) + 1;
		let mut number_file = OpenOptions::new().write(true).truncate(true).open(&msg_number_file).expect("File writing error");
		if number_file.write_all(&msg_number.to_string().as_bytes()).is_err() { return_error!("internal error"); }
		if number_file.flush().is_err() { return_error!("internal error"); }
		let mut msg_path = Path::new(RUNTIME_DIR).to_owned();
		msg_path.push(&req.id.to_string());
		msg_path.push(&msg_number.to_string());
		// write content and mdc to file
		let msg_file_content = sent_content.to_string() + "\r\n" + &query.s;
		let mut msg_file = File::create(msg_path).expect("File creation error");
		if msg_file.write_all(&msg_file_content.as_bytes()).is_err() { return_error!("internal error"); }
		if msg_file.flush().is_err() { return_error!("internal error"); }
	}
	//Ok(format!("OK: {}", msg_number.to_string()))
	//TODO: write macro to indicate success and return bytes
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	HttpServer::new(|| {
		App::new()
			.service(hello)
			.service(rcv)
	})
	.bind((SERVER_ADDRESS, SERVER_PORT))?
	.run()
	.await
}
