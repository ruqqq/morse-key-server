class Model
	table_name: null
	schema: {}

	constructor: (@App) ->
		@db = @App.nano.db.use "#{@App.config.couchdb.database_prefix}#{@table_name}"

	findAll: (params, callback) =>
		@db.list params, (err, body) =>
			if !err
				if callback then callback null, body
			else if err and err.status_code is 404
				if callback then callback null, null
			else
				if callback then callback "#{err.error}: #{err.reason}", null

	findOne: (key, callback) =>
		@db.get key, (err, body, header) =>
			if !err
				if callback then callback null, body
			else if err and err.status_code is 404
				if callback then callback null, null
			else
				if callback then callback "#{err.error}: #{err.reason}", null

	insert: (key, values, callback) =>
		@db.insert values, key, (err, body) =>
			if !err
				if callback then return callback null, body
			else
				if callback then return callback "#{err.error}: #{err.reason}", null

	replace: (key, values, callback) =>
		@findOne key, (err, data) =>
			if !err and data
				values._rev = data._rev

			@db.insert values, key, (err, body) =>
				if !err
					if callback then return callback null, body
				else
					if callback then return callback "#{err.error}: #{err.reason}", null

	del: (key, callback) =>
		@findOne key, (err, data) =>
			if !err and data
				@db.destroy key, data._rev, (err, body) =>
					if !err
						if callback then return callback null, body
					else
						if callback then return callback "#{err.error}: #{err.reason}", null
			else
				if callback then return callback null, null

module.exports = Model