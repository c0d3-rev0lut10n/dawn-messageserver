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

use crate::{DELETED, IS_HEX, IS_MDC, RUNTIME_DIR, SAVED_MSG_MINIMUM};
use GetMessageError::*;
use std::path::PathBuf;
use serde::Serialize;
use tokio::fs::File;
use fs4::tokio::AsyncFileExt;
use tokio::io::AsyncReadExt;


pub(crate) enum GetMessageError {
	InvalidInput,
	WrongMdc,
	Deleted,
	Other
}

#[derive(Serialize)]
pub(crate) struct Message {
	sent: i64,
	read: i64,
	content: Vec<u8>
}

pub(crate) async fn get_msg_validated(id: &str, msg_number: &u16, mdc: &[u8]) -> Option<Result<Message, GetMessageError>> {
	// check if id is hex-string
	if !IS_HEX.is_match(id) { return Some(Err(InvalidInput)); }
	
	// check if message detail code is valid
	
	let mut path = PathBuf::from(RUNTIME_DIR);
	path.push(id);
	path.push(msg_number.to_string());
	if !path.is_file() {
		// message does not exist
		return None;
	}
	
	// message does exist
	let message_file = File::open(&path).await;
	if message_file.is_err() { return Some(Err(Other)); }
	let mut message_file = message_file.unwrap();
	
	if message_file.lock_shared().is_err() { return Some(Err(Other)); }
	
	let mut file_bytes = vec![];
	if message_file.read_to_end(&mut file_bytes).await.is_err() {
		message_file.unlock().ok();
		return Some(Err(Other));
	}
	
	if message_file.unlock().is_err() { return Some(Err(Other)); }
	
	if file_bytes.len() <= SAVED_MSG_MINIMUM {
		if file_bytes == DELETED.to_vec() {
			// message got deleted
			return Some(Err(Deleted));
		}
		return Some(Err(Other));
	}
	let (saved_mdc, info) = file_bytes.split_at(4);
	
	// verify mdc
	if mdc != saved_mdc {
		return Some(Err(WrongMdc));
	}
	
	// split off timestamps
	let (timestamps_bytes, content) = info.split_at(16);
	let (sent_timestamp_bytes, read_timestamp_bytes) = timestamps_bytes.split_at(8);
	
	// parse 'sent' timestamp
	let sent_timestamp_slice: [u8;8] = sent_timestamp_bytes.to_owned().as_slice().try_into().unwrap();
	let sent_timestamp = i64::from_le_bytes(sent_timestamp_slice);
	
	// parse 'read' timestamp
	let read_timestamp_slice: [u8;8] = read_timestamp_bytes.to_owned().as_slice().try_into().unwrap();
	let read_timestamp = i64::from_le_bytes(read_timestamp_slice);
	
	// return message
	Some(Ok(Message {
		sent: sent_timestamp,
		read: read_timestamp,
		content: content.to_vec()
	}))
}
