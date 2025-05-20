# Key exchange
1. Run app on
```
cd src/tls_key_exchange/app
uv run app.py
```
2. Run device
```
cd ../../..
cd src/tls_key_exchange/device
uv run device.py
```
3. Write number shown on app to device prompt

4. Get keys
 * Signed keys are now found under app/upload
 * Generated keys can be found under app/tls and device/tls
```
# Check App files
cd ../..
cd src/tls_key_exchange
ls app/tls/client.key
ls app/upload/client.crt
ls app/upload/ca.crt
```
```
# Check Device files
ls device/tls/server.key
ls device/tls/server.crt
ls device/ca/ca.crt
ls device/ca/ca.key
```

# Run httpd server and get file
1. Cert/key files are already added from key exchange location
2. Run server
```
cd ../..
cd src/tls_key_exchange
uv run server_http.py
```
3. Run Client
```
uv run server_client.py
```
4. Inspect download file
```
cat download/README.md
```

