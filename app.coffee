zlib = require "zlib"

class App
	constructor: ->
		@config = require "./config"
		@nano = require('nano')("https://#{@config.couchdb.user}:#{@config.couchdb.password}@#{@config.couchdb.host}")

		@useRestify()

		new (require "./KeysHandler") this

	start: ->
		@server.listen @config.port, () =>
			console.log "%s listening on %s", @server.name, @config.port

	stop: ->
		@server.close () =>
			process.exit 1

	useRestify: =>
		@restify = require "restify"

		# Restify
		@server = @restify.createServer()
		@server.use @restify.acceptParser(@server.acceptable)
		@server.use @restify.queryParser({ mapParams: false })
		@server.use @restify.bodyParser()

		#@server.defaultResponseHeaders = (data) =>

	sendError: (req, res, code, msg) =>
		res.status code
		@compressIfRequested req, res, {"errorCode": code, "errorMsg": msg}

	compressIfRequested: (req, res, data) =>
		if @config.force_disable_compression
			return res.json data

		encoding = ""
		if req.headers["accept-encoding"] then encoding = req.headers["accept-encoding"]
		else if req.headers["Accept-Encoding"] then encoding = req.headers["Accept-Encoding"]

		string_data = JSON.stringify data
		res.setHeader "Content-Type", "application/json; charset=utf-8"
		res.header "Access-Control-Allow-Origin", "*"

		if (new RegExp("deflate")).test encoding
			res.setHeader "Content-Encoding", "deflate" 
			dataBuffer = new Buffer string_data
			zlib.deflate dataBuffer, (err, buffer) =>
				res.end buffer
		else if (new RegExp("gzip")).test encoding
			res.setHeader "Content-Encoding", "gzip" 
			dataBuffer = new Buffer string_data
			zlib.gzip dataBuffer, (err, buffer) =>
				res.end buffer
		else
			res.json data

app = new App
app.start()
