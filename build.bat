@echo off
powershell kill -n nweb23
c:\cygwin64\bin\cscope -R -b
c:\cygwin64\bin\make
cd matasano-crypto-challenges\set4\nweb
nweb23 8181 .
cd ..\..\..
