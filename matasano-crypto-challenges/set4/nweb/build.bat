@echo off
c:\cygwin64\bin\ctags -R .
powershell kill -n nweb23
c:\cygwin64\bin\make
nweb23 8181 .
