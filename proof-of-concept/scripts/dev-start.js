#!/usr/bin/env bash

exec nodemon -w . --exec "./scripts/start.js $@"