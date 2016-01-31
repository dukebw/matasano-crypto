@echo off
c:\cygwin64\bin\cscope -R -b
c:\cygwin64\bin\make
cd matasano-crypto-challenges\set4\nweb
call build.bat
cd ..\..\..
