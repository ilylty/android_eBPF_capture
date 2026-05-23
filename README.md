# android_eBPF_capture

Android ARM64 eBPF uprobe demo for capturing plaintext passed to Conscrypt `SSL_write` on Android 13.

## Build

The repository is intended to build in GitHub Actions. Push to `main`, then download the `android-ebpf-capture-binaries` artifact containing:

- `ssl.bpf.o`
- `ssl_sniff_bin`

## Deploy

```sh
adb push ssl.bpf.o /data/local/tmp/
adb push ssl_sniff_bin /data/local/tmp/
adb shell
su
setenforce 0
mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || mount -t debugfs nodev /sys/kernel/debug
cd /data/local/tmp
chmod +x ssl_sniff_bin
./ssl_sniff_bin
```

The loader attaches a uprobe to `/apex/com.android.conscrypt/lib64/libssl.so:SSL_write` and prints UTF-8 payloads as text, otherwise as hex.
