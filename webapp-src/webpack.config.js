/**
 * webpack.config.js
 * 
 * webpack configuration for build in production
 * 
 * Copyright 2019-2022 Nicolas Mora <mail@babelouest.org>
 * 
 */
const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: {
		admin: path.resolve(__dirname, 'src/admin.js'),
		login: path.resolve(__dirname, 'src/login.js'),
		profile: path.resolve(__dirname, 'src/profile.js'),
		callback: path.resolve(__dirname, 'src/callback.js')
	},
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: ['babel-loader'],
      },
      {
        test: /\.css$/,
        use: [ 'style-loader', 'css-loader' ]
      }
    ],
  },
  resolve: {
    extensions: ['*', '.js', '.jsx'],
  },
  output: {
		path: path.resolve(__dirname, 'output'),
		filename: '[name].js',
		libraryTarget: 'umd'
  },
  plugins: [new webpack.HotModuleReplacementPlugin()],
  devServer: {
    static: path.resolve(__dirname ),
    hot: true,
    compress: true,
    port: 3000,
    host: 'localhost',
    open: true,
    proxy: {
      '/api': {
        target: 'http://localhost:4593/',
        secure: false,
        changeOrigin: true
      },
      '/config': {
        target: 'http://localhost:4593/',
        secure: false,
        changeOrigin: true
      }
    }
  }
};
