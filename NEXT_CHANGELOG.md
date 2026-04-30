# NEXT CHANGELOG

## Release v0.132.0

### Breaking Changes

### New Features and Improvements

* Support Kerberos (SPNEGO) authentication against upstream HTTP proxies. Set
  `DATABRICKS_PROXY_AUTH_TYPE=negotiate` (or the `ProxyAuthType` field on
  `httpclient.ClientConfig`) to attach a `Proxy-Authorization: Negotiate`
  header to the proxy CONNECT tunnel, using the Kerberos configuration at
  `$KRB5_CONFIG` (default `/etc/krb5.conf`) and the ticket cache at
  `$KRB5CCNAME` (default `/tmp/krb5cc_<uid>`). Keytab-based auth is out of
  scope.

### Bug Fixes

### Documentation

### Internal Changes

### API Changes
