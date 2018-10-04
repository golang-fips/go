// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import "strings"

// LocalhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at Jan 29 16:00:00 2084 GMT.
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var LocalhostCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIRALnQ833F+ldkJgxLTBi7tbEwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAMEFghlvOWNGahq8Ma8ElZq24MxRRAgePxkP4RZMfSUUuTCcA2yE
/mSrPNc49coNZL2rjSgu57U6KgMVvXwWrNKO3+IW1rR6vRq0N+g03bGh3SrnwnIi
vtFbbuMNE2t48lKnRSSRaQVWa0C0O21JJ321ACN4AfaIMowRFUUr8fomwgIPXjtI
3rMnE0oQFNkecWs5s/QmzyyPPPNxJUhBRoWg3MLhY+Sq8AkP/WCF4yxnFoDS8t69
CJjpFVq9ueNIIkOS8B3ylUti7l0FCSUfD8Xs5eYPkcOB7BzA0amk21In6WzzUjX8
qw8db4dzu8o3w9RuWMQzYrV1tlhcDP5HW5kCAwEAAaNoMGYwDgYDVR0PAQH/BAQD
AgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wLgYDVR0R
BCcwJYILZXhhbXBsZS5jb22HBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZI
hvcNAQELBQADggEBAAgjasMo7y6NR8f6/3uzCSXD+Ynor02lBDC2yPkH6eEkQJpT
2oNt+YoQ5zw0SLV57/O9AykXWbmOgPQzkjjHkYq32qJCfc//O4of2v289R6cwqAB
xWha9R3bFvjJH7EFMFj18e37rDYeX85BZeX90+SKc4OtIqzJBKUz5a0FJd7+Zkzu
YrHaK5vIN0mY4WcK1wrFemf9GOQVdM1azEgPP+HoYQwMZMmqbV126OO6VO5tY4c+
arFYI9vA69ld00mrLmuaoQsODO/Xk30bPonTndmDuPqHYzkw7/OZk7YgmaCy2a21
b8jUqQAurcSkb59lX6+DDP2M+IhJK8/PTDaFyS4=
-----END CERTIFICATE-----`)

// LocalhostKey is the private key for localhostCert.
var LocalhostKey = []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
MIIEowIBAAKCAQEAwQWCGW85Y0ZqGrwxrwSVmrbgzFFECB4/GQ/hFkx9JRS5MJwD
bIT+ZKs81zj1yg1kvauNKC7ntToqAxW9fBas0o7f4hbWtHq9GrQ36DTdsaHdKufC
ciK+0Vtu4w0Ta3jyUqdFJJFpBVZrQLQ7bUknfbUAI3gB9ogyjBEVRSvx+ibCAg9e
O0jesycTShAU2R5xazmz9CbPLI8883ElSEFGhaDcwuFj5KrwCQ/9YIXjLGcWgNLy
3r0ImOkVWr2540giQ5LwHfKVS2LuXQUJJR8Pxezl5g+Rw4HsHMDRqaTbUifpbPNS
NfyrDx1vh3O7yjfD1G5YxDNitXW2WFwM/kdbmQIDAQABAoIBAFWrvDLNywrlFfMH
1IV542zn/p6w8yEnS5o0EhNzn5f1urx4goyH+uFzn21nOrCTgUMuAVj0eKNXTY5Q
9+k7pzlNcNFIkcNJNuXDV40Y6c0NqryAYS2Hfmotyum7xALPi75jv6ybXaGg2bm+
RSIcdgq1a3pSqYxipwzECEzLVHtSMYC9+eyfT86oLpSju1CrtbS+mDiOxf7yaGjg
Ujsa1/B8MufzGsTHRjnHuWQlcOK7AcaVB7Y4VaRV2tDW1TdIQslymUMO3hq3fSwF
lf74qXBFH2C/DC5UUSW7CXWUThv6gyArkEk7cJLxfI/vUAs+OlDitjFhfTcbmVxD
jgfbGoECgYEAwuXcLJ7mS9WM3ulXb/ZwyclnkRcI4yDdcvz2v96mw0IrZmjmObxo
UrnQpvZxLgN/AzYvoUBM1jz6t0YfTF6kH+prHwrlQY8qOrPsr3EpvSF2LSQagSdJ
xoWP0gtLV+F+fmyPxZLRphdxMg3lxh+jAgzRCFj4Gf5mXtOlr/9ts5sCgYEA/YkN
yMB+NGWzAx7w1E0Sa+xGDYmxgghhveTwuRipRXy71unXF6Qom5xKbxfbEgZxeGHP
+M6YpZMHcJvtOvuCjDCxymgIP1+oTEWn9oedGWSwCUBsFG9voddLnpecOhLNwYIX
FVNdNCeIDiYWjKq8swCHkQQ6l6LYj6JPendOgtsCgYEAqCv7ji0Wfv0n7vjdz+iQ
bi3xxcpgisvDCgOpTupqbzXbiSSe89bVFfzsRAWGp7Owly7cboGzS3GWzSoeu6E2
cauu/zxBkg5c3AaBBunYoDANbuomTKeAC2MYNKA2RQB4S9KVRGBpsq2rqQtA53JJ
D+3LOS679oIEB3MNFw6KtF0CgYBg8ltW/GRF3O2Kr/Ye+CmnIv3Wh2Rc+J+HYVe7
L3bqnzukfl5FJ/xvJGBCArk+N0CEa8J+vWEZTxN1N+qKt0nAGY6iew1MTmOoZqpH
Vqv33cyCfSPW3JWvKQg9aHPQsQgEip4RBYOKQeOApYfR2ie1uuobxaYx/Y8ZvVLu
3VgkKQKBgAQqLv/Yl2tj/34/Cw5tBTsrsAtK0MOx7iW/sbbL4Ea4tieB8DdVKkFH
NYFkIWFOG4/Pq/sZqhGIzCdc327vQKR6gAMKVcweXM8FjZB9aiRTA8ut8tXAdGmk
0jehdq8r2/jLC1CQ4Px0tgJGc7ekrxUk1rT9OpLHSG3drcBKUM03
-----END RSA TESTING KEY-----`))
func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }