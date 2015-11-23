#!/bin/bash
cd ../..
ctags -R .
cd matasano-crypto-challenges/set4
P=break_hmac_sha1_artifical_timing_leak make
