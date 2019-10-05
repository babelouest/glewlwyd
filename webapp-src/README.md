# Glewlwyd front-end source files

Glewlwyd front-end is a single Page Application based on ReactJS/JQuery. Uses Webpack 4 to build, requires npm or yarn.

## Install dependencies

Prior to running the development instance or building the front-end, you must install the dependencies.

```shell
$ npm install
```

## Run development instance

Copy `config.json.sample` to `config.json` and run the webpack dev server:

```shell
$ cp config.json.sample config.json
$ npm run dev
```

Then open the address [http://localhost:3000/](http://localhost:3000/) on your browser.

## Build front-end

```shell
$ make
```

The built web application will be available in `glewlwyd/webapp`.

## Build front-end for Internet Explorer support

Internet Explorer 11 doesn't have javascript engine compatible with Glewlwyd Front-end application, by choice.

If you really need to support Internet Explorer, you can build the front-end with [babel-polyfill](https://babeljs.io/docs/en/babel-polyfill). This will make the front-end application somehow bigger and slower, that's the reason why this build option is disabled by default.

To build the front-end application with babel-polyfill, run the following command:

```shell
$ make build-polyfill-webapp
```

The built web application will be available in `glewlwyd/webapp`.
