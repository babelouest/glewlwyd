# Docker image builder for Glewlwyd

This docker image is based on Alpine Linux 3.10 and Glewlwyd latest alpine package available on https://github.com/babelouest/glewlwyd/releases/ .

## Build the docker image

```shell
$ make build
```

## Run the docker image with minimal configuration on your local machine, only for testing.

```shell
$ make run
$ # or
$ docker run --rm -it -p 4593:4593 babelouest/glewlwyd
```

Then open the address [http://localhost:4593/](http://localhost:4593/) on your browser.

## Run the docker image using your configuration files

This will use the configuration files placed in the subfolder folder [config](config).

You can specify a different database, certificate files, `external_url`, UI settings, or any other configuration settings that will make this docker instance suitable for your needs.

```shell
$ make my-config
$ # or
$ docker run --rm -it -p 4593:4593 -v $(pwd)/config:/etc/glewlwyd babelouest/glewlwyd
```
