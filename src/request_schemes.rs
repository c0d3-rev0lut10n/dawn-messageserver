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

use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct ReceiveRequestScheme {
	pub id: String,
	pub msg_number: u16,
}

#[derive(Deserialize)]
pub(crate) struct SendRequestScheme {
	pub id: String,
}

#[derive(Deserialize)]
pub(crate) struct MDCQuery {
	pub mdc: String,
}

#[derive(Deserialize)]
pub(crate) struct SetHandleRequestScheme {
	pub id: String,
	pub handle: String,
}

#[derive(Deserialize)]
pub(crate) struct AddKeyRequestScheme {
	pub handle: String,
}

#[derive(Deserialize)]
pub(crate) struct HandlePasswordQuery {
	pub password: String,
}

#[derive(Deserialize)]
pub(crate) struct HandleEditQuery {
	pub password: String,
	pub allow_public_init: bool,
	pub init_secret: String
}

#[derive(Deserialize)]
pub(crate) struct HandleInfoQuery {
	pub init_secret: String
}

#[derive(Deserialize)]
pub(crate) struct FindHandleRequestScheme {
	pub handle: String,
}

#[derive(Deserialize)]
pub(crate) struct DeleteMessageRequestScheme {
	pub id: String,
	pub msg_number: u16,
}

#[derive(Deserialize)]
pub(crate) struct DeleteHandleRequestScheme {
	pub handle: String,
}
