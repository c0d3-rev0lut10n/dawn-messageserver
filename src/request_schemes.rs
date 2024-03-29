/*	Copyright (c) 2023-2024 Laurenz Werner
	
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
pub struct ReceiveRequestScheme {
	pub id: String,
	pub msg_number: u16,
}

#[derive(Deserialize)]
pub struct SendRequestScheme {
	pub id: String,
}

#[derive(Deserialize)]
pub struct SendQuery {
	pub mdc: String,
	pub referrer: Option<String>,
}

#[derive(Deserialize)]
pub struct MDCQuery {
	pub mdc: String,
}

#[derive(Deserialize)]
pub struct OptionalMDCQuery {
	pub mdc: Option<String>,
}

#[derive(Deserialize)]
pub struct SetHandleRequestScheme {
	pub id: String,
	pub handle: String,
}

#[derive(Deserialize)]
pub struct AddKeyRequestScheme {
	pub handle: String,
}

#[derive(Deserialize)]
pub struct HandleStateRequestScheme {
	pub handle: String,
}

#[derive(Deserialize)]
pub struct GenerateOneTimeInitRequestScheme {
	pub handle: String,
}

#[derive(Deserialize)]
pub struct HandlePasswordQuery {
	pub password: String,
}

#[derive(Deserialize)]
pub struct HandleEditQuery {
	pub password: String,
	pub allow_public_init: bool,
	pub init_secret: String
}

#[derive(Deserialize)]
pub struct HandleInfoQuery {
	pub init_secret: String
}

#[derive(Deserialize)]
pub struct FindHandleRequestScheme {
	pub handle: String,
}

#[derive(Deserialize)]
pub struct DeleteMessageRequestScheme {
	pub id: String,
	pub msg_number: u16,
}

#[derive(Deserialize)]
pub struct DeleteHandleRequestScheme {
	pub handle: String,
}

#[derive(Deserialize)]
pub struct SubscriptionRequestScheme {
	pub subscription_id: String,
	pub sub_msg_number: u32,
}
