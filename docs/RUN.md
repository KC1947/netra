# Run the offline demo

From the repository root, start the local service with:

```sh
./scripts/demo.sh
```

It activates `.venv`, rebuilds any missing synthetic captures and demo-library
files, then starts the service at [http://127.0.0.1:8000](http://127.0.0.1:8000).
The demo does not make network calls. It analyses packet captures already on
disk and serves only on loopback.

Stop it with `Ctrl-C` in the terminal that started it.

To add a capture, use the interface at `/` when a frontend is present, or post
the file to the local upload endpoint. The endpoint accepts pcap and pcapng
signatures only, limits files to 200 MB, and stores accepted uploads under
`demo_captures/uploads/`:

```sh
curl -F 'file=@/path/to/capture.pcap' http://127.0.0.1:8000/api/captures/upload
```

If port 8000 is busy, stop the existing local process or launch a different
port directly:

```sh
.venv/bin/python -m uvicorn server.app:app --host 127.0.0.1 --port 8001
```

Then use `http://127.0.0.1:8001`. The API remains local; changing the port
does not enable network access during analysis.
