![Supported](https://img.shields.io/badge/development_status-supported-brightgreen.svg) ![License BSDv2](https://img.shields.io/badge/license-BSDv2-brightgreen.svg)

## goklp: Golang OpenSSH Keys Ldap Provider for AuthorizedKeysCommand

This is a copy of the now defunct 'goklp' tool by AppliedTrust, which can be used as source of SSH authorized keys. Bugs will be fixed if necessary.

### Usage:
1. Setup goklp.ini - must be in same directory as goklp
1. Test to ensure goklp returns SSH keys: goklp <username>
1. Add this line to your sshd_config: AuthorizedKeysCommand /path/to/goklp

### goklp.ini config file is required:

```
goklp_ldap_uri          = ldaps://server1:636,ldaps://server2:636   (required)
goklp_ldap_bind_dn      = CN=someuser,O=someorg,C=sometld           (required)
goklp_ldap_base_dn      = O=someorg,C=sometld                       (required)
goklp_ldap_bind_pw      = someSecretPassword                        (required)
goklp_ldap_timeout_secs = 10                           (optional - default: 5)
goklp_debug             = false                    (optional - default: false)
```

