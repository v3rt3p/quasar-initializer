# quasar-initializer

Yandex.Station initializer using:
- beeping sounds (`quasar-sound.js/html`)
- QR code (for Yandex.Station Duo Max) (`quasar-qr.js/html`)

## Usage

Open `quasar-sound.html` directly in a browser or serve this directory with a static server:

```bash
python -m http.server 8000
```

Then open `http://localhost:8000/quasar-sound.html`. The page collects the Wi-Fi SSID, password, token code, network security mode, hidden-network flag, volume, and tone duration. It has no backend, Dockerfile, or runtime service.
