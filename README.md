mod_dumpost
===========

Small apache module to log body content of request (POST / FORM data). Data are written to error log by default. For example:
```
[Sat Dec 08 09:58:24 2012] [info] [client 1.1.2.2] ------------------------------4bc4ed022729\r\nContent-Disposition: form-data; name="f"; filename="poc.html"\r\nContent-Type: text/html\r\n\r\n
[Sat Dec 08 09:58:43 2012] [info] [client 1.1.1.1] a=100
```

Note: You can do the same with mod_security, use this when you want a quick and lightweight solution.

### Installation:
```
make
make install
```

### Configuration:
In `httpd.conf` (optional):
* `DumpPostMaxSize 1024`: limit the size of a log entry to `1024` bytes (default value: `1048576` i.e. 1MB)
* `DumpPostHeaderAdd Cookie Content-Type`:  add HTTP Header to log together with POST (default value: None)
* `DumpPostLogFile`: specify a custom file to write the log entry (other than error log)
* `DumpPostLogBinary`: [On/Off] Save binary requests data in hex string format.
* `DumpPostFilter`: add a filter to match on first header of request, if no filter is present all traffic will be dumped.

### Requirement:
* apxs:
    * Ubuntu: `sudo apt-get install apache2-threaded-dev`, edit Makefile change
      `apxs` to `apxs2`
* `LogLevel` of at least `Info` (not important if using DumpPostLogFile) use `Debug` to investigate common problems with files and request sizes.
