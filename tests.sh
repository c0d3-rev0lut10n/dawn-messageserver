#!/bin/bash

#	Copyright (c) 2023 Laurenz Werner
#	
#	This file is part of Dawn.
#	
#	Dawn is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#	
#	Dawn is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#	
#	You should have received a copy of the GNU General Public License
#	along with Dawn.  If not, see <http://www.gnu.org/licenses/>.

#	THIS SCRIPT PROVIDES AUTOMATIC TESTS FOR THE DAWN MESSAGESERVER

# Error return function
error() { printf "\033[0;31m%s\n\033[0m" "$*" >&2; }

# info function
notice() { printf "\033[0;32m%s\n\033[0m" "$*" >&1; }

# cd into the directory this script is located at
cd ${0%/*}

# prepare test environment
mkdir -p runtime
rm -R runtime/*
mkdir runtime/handle

# set a handle
notice "INFO: testing sethandle"
curl -v -X POST 'http://localhost:8080/sethandle/1234121212121212121212121212121212121212121212121212121212121212/qwerty?password=password&allow_public_init=false&init_secret=blahblahblahblah' --data-binary "@./test-data/test1" || error "ERROR: sethandle failed"
