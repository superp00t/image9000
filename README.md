![img9k](cmd/img9k/assets/logo.png)

Fucking garbage image hosting server. Abandon hope, all ye who use this software.

### Building

```bash
go get -u -v github.com/superp00t/image9000/cmd/img9k
```

### Running the server

```bash
img9k run <dir which contains config.json and /i/>
```

Special options are located in config.json. If you don't have a Image9000 directory and config.json, `img9k run` will create one for you automatically.

An example nginx configuration is located at `example.conf`.