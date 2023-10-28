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

## Run

In order to work properly, the binary needs to have the `runtime` directory and a subdirectory called `handle` at the currect location.

This is currently `./runtime` (from the PWD), it will be configurable in a later version.

Also, make sure that the user you use to execute the binary has sufficient permissions to read and write any files below the `runtime` directory.


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

#### Possible responses:

* `200 OK`

	`dawn:0.0.1`

### Receive messages

The endpoint `GET` `/rcv/{id}/{msg_number}` is used to receive messages. Replace *{id}* with the temporary ID you want to receive a message for, and ask for the next message number you didn't already receive using *{msg_number}*. If you did not request any message so far, start with number 0. When you send messages to an ID, simply save the returned message number as you won't need to receive your own message ;)

#### Possible responses:

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

#### Possible responses:

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

#### Possible responses:

* `200 OK`

	*The message was marked as read successfully.*

* `204 No Content`

	*The message does not exist. If it is a deleted message, the header* `X-Deleted` *is set.*

* `400 Bad Request`

	*Either your message detail code was wrong, or the message is already marked as read. For details, please refer to the body of the response.*

* `500 Internal Server Error`

	*Something is wrong with the server. This could i.e. be a permission problem in the runtime directory.*

### Send a message

You can send messages by using the `POST` `/snd/{id}?mdc={mdc}` endpoint. The message detail code is generated client-side and can be chosen arbitrarily. The encrypted message is sent in the `POST` request body.

#### Possible responses:

* `204 No Content`

	*The message was sent successfully. The message ID it got assigned can be found in the header* `X-MessageNumber`*.*

* `400 Bad Request`

	*A client side error occured, for example: your request parameters were invalid, your message was too big, there are already too many messages*

* `500 Internal Server Error`

	*Something is wrong with the server. This could i.e. be a permission problem in the runtime directory.*

### Delete a message

`DELETE` `/del/{id}/{msg_number}?mdc={mdc}` is used to delete messages on the server. You need to provide the ID and message number as well as the message detail code to prove your authorization to delete the message.

#### Possible responses:

* `204 No Content`

	*The message was deleted successfully.*

* `400 Bad Request`

	*A client-side error occured, i.e. the message detail code is wrong or the message does not exist.*

* `500 Internal Server Error`

	*Something is wrong with the server. This could i.e. be a permission problem in the runtime directory.*

### Create a subscription

Receiving messages one by one is not very efficient because you need at least one request per message and you need to poll the endpoint for each ID individually to stay up-to-date when it comes to new messages. Therefore, you should use subscriptions whereever possible. The only exception would be receiving an old message another time. To use subscriptions, distribute the IDs you need to poll in a random pattern over multiple subscriptions. One subscription can hold a maximum total of 100 IDs. Creating a subscription is done using the `POST` `/subscribe` endpoint. Subscriptions live for 4 hours by default, but there is no guarantee for that lifetime. The server may evict older subscriptions from the memory if a low-memory scenario occurs.

#### Usage

The `POST` body has to contain UTF-8 encoded text that is formatted like this:
<pre><code>id_42 my_mdc 0
id_abcdef other_mdc 20
next_id mdc</code></pre>

The first part of a line is the ID you want to subscribe to. After that, a space is added to split off the next part which is the message detail code that you expect to match the messages' mdc. If you already received some messages, put the number of the first new message you want to get. For example, if you received messages 0 to 19 for an ID, use the number 20.

#### Possible responses:

* `200 OK`

	*The subscription was created. The ID of your new subscription is in the body of the response.*

* `400 Bad Request`

	*A client-side error occured, i.e. your POST body is formatted incorrectly.*

* `500 Internal Server Error`

	*Something is wrong with the server. This could i.e. be a permission problem in the runtime directory.*

### Receive messages via subscription

Receiving messages in bulk via subscription is done using the `GET` `/sub/{subscription_id}/{sub_msg_number}` endpoint. Provide the subscription ID you received when creating the subscription and the first message number you didn't already receive. Subscription message numbers are independent from the numbers associated with the messages in their chats, they simply increment for each new message from any of the associated chats.

#### Possible responses:

* `200 OK`

	*There are new messages. Those are provided in the body as a JSON object containing an array of message objects. Each object has a status and, if the status is "ok", a nested object containing the message's ID, message number, timestamps and content (latter is encoded using base64). Example:*
	<pre>{"messages":[
		{
			"status":"ok",
			"message":{
				"id":"42",
				"msg_number":"0",
				"sent":1696241555,
				"read":0,
				"content":"UlwJDgyq0F1/IHgO9IqCFANRpl/aUwu9Nd7HAITmscvVpHHL7FRhbhli/QHfqKhP1JgO6zYPKA/7lTeXI/qMtz6hzb+l3GSCEQaonriUrqN70Y2aWb6C30kfNlbEUvYnEyXjTpTrIwv5E+vFJ/wv2sgRqYrjEp7uxH0q5Jkz5YoF+b5i8RWdg8Jogh0Uy0+WZdZQCxZtElm/WbT25DIBOxWG54+aU06eDVEUhLGnofzrK7XizDQytxcTkY0WweyHseTN5Rsc6vdw0X6hkrj1LJLuZ1m2HnFqgztr7dncqUR7i97AqU+jTWE7t/J65ouC7D1iVqDJ82yMzsVCj23igw"
			}
		},
		{
			"status":"ok",
			"message":{
				"id":"42",
				"msg_number":"1",
				"sent":1696241987,
				"read":0,
				"content":"UlwJDgyq0F1/IHgO9IqCFANRpl/aUwu9Nd7HAITmscvVpHHL7FRhbhli/QHfqKhP1JgO6zYPKA/7lTeXI/qMtz6hzb+l3GSCEQaonriUrqN70Y2aWb6C30kfNlbEUvYnEyXjTpTrIwv5E+vFJ/wv2sgRqYrjEp7uxH0q5Jkz5YoF+b5i8RWdg8Jogh0Uy0+WZdZQCxZtElm/WbT25DIBOxWG54+aU06eDVEUhLGnofzrK7XizDQytxcTkY0WweyHseTN5Rsc6vdw0X6hkrj1LJLuZ1m2HnFqgztr7dncqUR7i97AqU+jTWE7t/J65ouC7D1iVqDJ82yMzsVCj23igw"
			}
		}
	]}
	</pre>

* `204 No Content`

	*There are no messages with a higher number than your provided* `sub_msg_number`*.*

* `400 Bad Request`

	*A client-side error occured, i.e. your provided subscription ID does not exist.*

* `500 Internal Server Error`

	*Something is wrong with the server. This is likely a bug as specific errors for single messages are reported using the* `status` *attribute in JSON*

### Check the time

In order to make sure you compute the temporary IDs consistently with the rest of the world, your system time needs to be correct or you need to know the correct time somehow. To check the time (accurate to a view seconds, whcih is enough), the `GET` `/time` endpoint can be used.

#### Possible responses:

* `200 OK`

	*The body is a unix timestamp of the time the server received your request.*

### Set/edit a handle

You can set a handle for any ID (normally, it is an ID specifically used for init requests) by using the `GET` `/sethandle/{id}/{handle}?password={password}&allow_public_init={public_init}&init_secret={init_secret}`. The same endpoint can be used to edit an existing handle, in which case you need to know the correct handle password.

#### Parameters:

* `id`: the ID the handle should point to

* `handle`: the name of the handle (alphanumeric characters, dashes and underscores are allowed)

* `password`: the handle password. If you create a new handle, you can set this to any string you want. If you want to edit a handle, you need to provide the password that was used to create the handle previously.

* `public_init`: boolean value that decides whether or not people need to know the `init_secret` in order to ask for an init key

* `init_secret`: a string that is necessary to ask for an init key if `public_init` is set to `false`

#### Possible responses:

* `204 No Content`

	*The request was completed successfully*

* `400 Bad Request`

	*One or more of the parameters the client supplied were invalid*

* `500 Internal Server Error`

	*Something is wrong with the server. This could i.e. be a permission problem in the runtime directory.*

### Add keys to a handle

To add keys to a handle, the `POST` `/addkey/{handle}?password={password}` can be used.

#### Possible responses

* `204 No Content`

	*The request was completed successfully*

* `400 Bad Request`

	*One or more of the parameters the client supplied were invalid. This can also mean that the handle has already all key slots filled.*

* `500 Internal Server Error`

	*Something is wrong with the server. This could i.e. be a permission problem in the runtime directory.*
