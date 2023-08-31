#!/bin/bash
rm ./state_mock.go
mockgen -source=state.go -destination=state_mock.go -package=server