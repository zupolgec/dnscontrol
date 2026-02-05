## Configuration

To use this provider, add an entry to `creds.json` with `TYPE` set to `MIKROTIK`
along with the connection details for your MikroTik device.

Example:

{% code title="creds.json" %}
```json
{
  "mikrotik": {
    "TYPE": "MIKROTIK",
    "host": "192.168.88.1",
    "username": "admin",
    "password": "your-password"
  }
}
```
{% endcode %}

## Additional configuration options

| Option | Description | Default |
| ------ | ----------- | ------- |
| `host` | IP address or hostname of the MikroTik device | (required) |
| `username` | API username | `admin` |
| `password` | API password | (required) |
| `port` | API port | `8728` (plain) or `8729` (TLS) |
| `use_tls` | Use TLS encryption | `false` |
| `insecure` | Skip TLS certificate verification | `false` |
| `timeout` | Connection timeout in seconds | `10` |

Example with TLS:

{% code title="creds.json" %}
```json
{
  "mikrotik": {
    "TYPE": "MIKROTIK",
    "host": "router.example.com",
    "username": "dnscontrol",
    "password": "secure-password",
    "use_tls": "true",
    "port": "8729"
  }
}
```
{% endcode %}

## Metadata

This provider does not recognize any special metadata fields unique to MikroTik.

## Usage

MikroTik RouterOS uses static DNS entries rather than traditional DNS zones. This provider manages entries in `/ip/dns/static` on your MikroTik device.

{% code title="dnsconfig.js" %}
```javascript
var REG_NONE = NewRegistrar("none");
var DSP_MIKROTIK = NewDnsProvider("mikrotik");

D("example.local", REG_NONE, DnsProvider(DSP_MIKROTIK),
    A("server1", "192.168.88.10"),
    A("server2", "192.168.88.11"),
    CNAME("www", "server1.example.local."),
    MX("@", 10, "mail.example.local."),
END);
```
{% endcode %}

## Activation

1. Enable the API service on your MikroTik device:
   ```
   /ip service enable api
   ```

2. For TLS connections, also enable the API-SSL service:
   ```
   /ip service enable api-ssl
   ```

3. Create a dedicated user for DNSControl (recommended):
   ```
   /user add name=dnscontrol password=secure-password group=full
   ```

4. Optionally restrict the API to specific IP addresses:
   ```
   /ip service set api address=192.168.88.0/24
   ```

## Supported record types

| Type  | Description |
| ----- | ----------- |
| A     | IPv4 address record |
| AAAA  | IPv6 address record |
| CNAME | Canonical name (alias) record |
| MX    | Mail exchange record |
| NS    | Name server record |
| SRV   | Service record |
| TXT   | Text record |

## Unsupported record types

The following record types are **not supported** by MikroTik RouterOS static DNS:

- `ALIAS` - Not available
- `CAA` - Not available
- `DHCID`, `DNAME`, `DNSKEY`, `DS`, `HTTPS`, `LOC`, `NAPTR`, `PTR`, `SOA`, `SSHFP`, `SVCB`, `TLSA` - Not available

## Limitations

### No zone concept

MikroTik RouterOS does not have traditional DNS zones. Instead, it uses a flat list of static DNS entries. DNSControl filters entries by domain suffix to simulate zone management.

This means:
- `get-zones` command is not supported
- `create-domains` is not supported
- All DNS entries matching the domain suffix will be managed

### TTL values

MikroTik accepts TTL values in various formats (e.g., `1d`, `1h`, `300s`). DNSControl converts TTL values to seconds format for consistency.

### API service must be enabled

The RouterOS API service must be enabled on the device. By default, it listens on port 8728 (plain) or 8729 (TLS).

### MikroTik-specific record types

MikroTik supports additional record types like `FWD` (forwarding) and `NXDOMAIN` that are not standard DNS record types. These are not supported by this provider.

## Concurrent operations

This provider supports concurrent operations for improved performance when managing multiple domains.
