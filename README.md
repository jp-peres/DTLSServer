# DTLSServer
## PROTOCOLS TESTED: 
- DTLSv1.0, DTLSv1.2

## CIPHERSUITES TESTED:
### DTLSv1.0 - 
- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_CBC_SHA
### DTLSv1.2 - 
- TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

## HOW TO RUN:
- make sure to have our config.properties in addition to the dtls.conf on the same directory of the jar's
- make sure paths for our key/truststores are correct

To run DTLSProxy jar, use either (Proxy ID 48320 with pass jpjpjp or 54449 with pass lcdlcdlcd)

Example:

java -jar DTLSProxy-0.0.1.jar 54449 lcdlcdlcd movies/cars.dat  clientkeystore.jks jplcdlcd clienttruststore.jks jplcdlcd

To run DTLSServer jar:

java -jar DTLSServer-0.0.1.jar localhost:9999 localhost:8888 serverkeystore.jks jplcdlcd servertruststore.jks jplcdlcd
