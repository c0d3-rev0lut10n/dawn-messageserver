# Server for the Dawn messenger

*licensed under GPL version 3 or higher*

This is the repository containing the source code of the messaging server for Dawn. This code is still experimental and any use for production, especially for applications where security is critical, is **NOT** recommended as of now.

Client-side source code can be found in the following repositories:

* [Dawn cryptographic library](https://github.com/c0d3-rev0lut10n/dawn-crypto)
* [Dawn standard library](https://github.com/c0d3-rev0lut10n/dawn-stdlib)
* [Dawn stdlib bindings for android](https://github.com/c0d3-rev0lut10n/dawn-stdlib-android)

## Install

As of now, only building directly from source is intended. Pre-compiled binaries for all major platforms will come in the future.

### Prerequisites

* git
* A working Rust installation with cargo
* OpenSSL development package

	Install on Ubuntu with: `sudo apt install libssl-dev`

### Building

The following guide is an example of the procedure on a Linux system. 

1. Clone this repository

	`git clone https://github.com/c0d3-rev0lut10n/dawn-messageserver`
	`cd dawn-messageserver`

2. Clean the build environment (only needed if you compiled it already previously)

	`cargo clean`

3. Build

	`cargo b --release`

4. Run your binary and enjoy!

	`./target/release/dawn-messageserver-n2g`


## Update

1. Pull the new version of the source code

	`git pull`


2. *optional* Clean the build environment

	`cargo clean`

3. Build and enjoy your update (overwrites the installed version)

	`cargo b --release`

## API reference

### General

The server will listen on `localhost:8080` by default. This is planned to be adjustable in a future version. For HTTPS support, simply use a reverse proxy.

The official Dawn main server has the base URL `https://messageserver.dawn-privacy.org`.

### Test the server connectivity

The endpoint `GET` `/dawn` simply returns a version string.

Possible responses:

* `200 OK`

	`dawn:0.0.1`

### Receive messages

The endpoint `GET` `/rcv/{id}/{msg_number}` is used to receive messages. Replace *{id}* with the temporary ID you want to receive a message for, and ask for the next message number you didn't already receive using *{msg_number}*. If you did not request any message so far, start with number 0. When you send messages to an ID, simply save the returned message number as you won't need to receive your own message ;)

Possible responses:

* `200 OK`

	*Returns the binary message in the response body*

* `204 No Content`

	*This message does not exist yet. Keep polling...*

* `400 Bad Request`

	*You did something wrong. For example, your provided ID is not a lowercase hex-string.*

* `500 Internal Server Error`

	*Something is wrong with the server. This could i.e. be a permission problem in the runtime directory.*

### Get message details

The endpoint `GET` `/d/{id}/{msg_number}?mdc={mdc}` can give you details about a message. You need to provide the ID and message number the same way you do when receiving messages. Additionally, to verify your authorization to get those details, you need to provide the message detail code (which is transmitted as a part of the message you received/sent) by replacing the placeholder {mdc} with it.

Possible responses:

* `200 OK`

	*The request was successful. Information about the message can be found in the headers.*
	
	`X-Sent`: This contains the timestamp the message was sent at.
	
	`X-Read`: This contains the timestamp the message was marked as read. If it is unread, this header will not be sent.

* `204 No Content`

	*The message you tried to get details about does not exist or got deleted.*
	
	`X-Deleted`: If this is set, the message got deleted.

* `400 Bad Request`

	*The ID or message detail code was invalid/wrong.*

* `500 Internal Server Error`

	*Something is wrong with the server. This could i.e. be a permission problem in the runtime directory.*

### Mark a message as read

The endpoint `GET` `/read/{id}/{msg_number}?mdc={mdc}` allows you to mark a message you received as read. The placeholders are used identically in comparison to the `/d/{id}/{msg_number}?mdc={mdc}` endpoint.

Possible responses:

* `200 OK`

	*The message was marked as read successfully.*

* `204 No Content`

	*The message does not exist. If it is a deleted message, the header* `X-Deleted` *is set.*

* `400 Bad Request`

	*Either your message detail code was wrong, or the message is already marked as read. For details, please refer to the body of the response.*

* `500 Internal Server Error`

	*Something is wrong with the server. This could i.e. be a permission problem in the runtime directory.*

