#!/usr/bin/env bash

docker run -p 5000:5000 -v "$(pwd)"/app.py:/app/app.py:rw flask