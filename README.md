# Broxy

[![Build Status](https://travis-ci.org/tsileo/broxy.svg?branch=master)](https://travis-ci.org/tsileo/broxy)

The most friendly proxy ever!

## Features

 - Reverse proxy or static content
 - Automatic TLS certificate management (creation,renewal) via [Let's Encrypt](https://letsencrypt.org/)
 - Optional built-in analytics with a web UI (Redis required)
 - Optional in-memory caching support
 - Spawn a syslog server for your app and get the logs merged with the requests
 - HTTP basic authentication support with brute force protection
 - Add security headers on the fly
 - Automatically ban IPs that make too many requests
 - Simple YAML configuration format with hot-reloading


# Development

Here is a sample local development file, the trick is to listen to localhost and use the same address to bind an app.

```yaml
auto_tls: false
listen: 'localhost:8020'
apps:
 - id: 'blog'
   domains:
    - 'localhost:8020'
   proxy: 'http://localhost:5005/'
   cache:
     cache_proxy: true
     time: 12h
```
