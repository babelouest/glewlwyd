/**
 * webpack.polyfill.config.js
 * 
 * webpack configuration for build in production
 * with polyfill plugin so old javascript engine (i.e. < es6)
 * can run the build app
 * 
 * Copyright 2019 Nicolas Mora <mail@babelouest.org>
 * 
 */

var path = require('path');
var webpack = require('webpack');
const UglifyJsPlugin = require('uglifyjs-webpack-plugin');

module.exports = {
	mode: 'production',
	entry: {
		admin: ["@babel/polyfill", path.resolve(__dirname, 'src/admin.js')],
		login: ["@babel/polyfill", path.resolve(__dirname, 'src/login.js')],
		profile: ["@babel/polyfill", path.resolve(__dirname, 'src/profile.js')],
		callback: ["@babel/polyfill", path.resolve(__dirname, 'src/callback.js')]
	},
	output: {
		path: path.resolve(__dirname, 'output'),
		filename: '[name].js',
		libraryTarget: 'umd'
	},

	module: {
		rules: [
			{
				test: /\.js$/,
				include: [ path.resolve(__dirname, "src") ],
				exclude: [ path.resolve(__dirname, "node_modules") ],
				loader: 'babel-loader',
				options: {
					presets: ['@babel/env','@babel/react']
				}
			},
			{
				test: /\.css$/,
				loader: 'style-loader!css-loader'
			}
		]
	},

	 plugins: [
		new webpack.DefinePlugin({
			"process.env": { 
				NODE_ENV: JSON.stringify("production") 
			}
		})
	],
	optimization: {
    minimize: true,
    minimizer: [new TerserPlugin()],
		splitChunks: {
			chunks: 'all'
		}
	}
}
