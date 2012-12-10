uuid = require "node-uuid"
crypto = require "crypto"
dcrypt = require "dcrypt"

class Keys
	constructor: (@App) ->
		@Keys = new (require "./keys") @App
		@Packages = new (require "./packages") @App

		@App.server.get "/", @getKey

	_generateRandomPassword: () =>
		return dcrypt.random.randomBytes(@App.config.password_length).toString("base64")

	_generateUniqueToken: () =>
		token = uuid.v1()
		return crypto.createHash("md5").update(token).digest("hex")

	_getPubKey: (id, callback) =>
		client = @App.restify.createJsonClient
		  url: @App.config.mainURL
		  version: "*"
		client.get "/users/getPubKey?id=#{id}", (err, req, res, obj) =>
			#console.log JSON.stringify obj
			if callback then callback err, obj

	_getGroupPubKey: (id, callback) =>
		client = @App.restify.createJsonClient
		  url: @App.config.mainURL
		  version: "*"
		client.get "/groups/getPubKey?id=#{id}", (err, req, res, obj) =>
			#console.log JSON.stringify obj
			if callback then callback err, obj

	getKey: (req, res, next) =>
		if req.query.package_id
			@Packages.findOne "package_#{req.query.package_id}", (err, reply) =>
				if reply
					@Packages.del "package_#{req.query.package_id}"
					return @App.compressIfRequested req, res, reply
				else
					return @App.sendError req, res, 400, "Invalid package token provided"
			return

		if !req.query.sender_id
			return @App.sendError req, res, 400, "Invalid ids provided"

		if !req.query.recipient_id and !req.query.group_id
			return @App.sendError req, res, 400, "Invalid ids provided"

		if !req.query.me or (!req.query.sender_id is req.query.me and !req.query.recipient_id is req.query.me)
			return @App.sendError req, res, 400, "Invalid id provided"
		#console.log JSON.stringify req.query

		isSender = req.query.me is req.query.sender_id
		packageToken = @_generateUniqueToken()

		retrieveMsgKey = (senderPubKey, recipientPubKey, groupPubKey, mePubKey) =>
			conditions = {}
			conditions.sender_id = req.query.sender_id
			if req.query.recipient_id
				conditions.recipient_id = req.query.recipient_id

			if req.query.group_id
				conditions.group_id = req.query.group_id

			@Keys.findOneWith conditions, (err, data) =>
				if data
					result =
						sender_id: data.sender_id
					
					if data.recipient_id
						result.recipient_id = data.recipient_id
					if data.group_id
						result.group_id = data.group_id

					result.key_encrypted = if isSender then data.senderkey else data.recipientkey
					result.status = data.status

					@Packages.insert "package_#{packageToken}", result
					packageToken = dcrypt.rsa.encrypt(mePubKey, new Buffer(packageToken).toString("base64"), @App.config.rsa_padding, 'base64')
					@App.compressIfRequested req, res, {package_id_encrypted: packageToken}
				else
					password = @_generateRandomPassword()
					
					row = @Keys.schema
					row.sender_id = req.query.sender_id
					
					if req.query.recipient_id
						row.recipient_id = req.query.recipient_id
					if req.query.group_id
						row.group_id = req.query.group_id

					row.senderkey = dcrypt.rsa.encrypt(senderPubKey, new Buffer(password).toString("base64"), @App.config.rsa_padding, 'base64')
					if recipientPubKey
						row.recipientkey = dcrypt.rsa.encrypt(recipientPubKey, new Buffer(password).toString("base64"), @App.config.rsa_padding, 'base64')
					if groupPubKey
						row.recipientkey = dcrypt.rsa.encrypt(groupPubKey, new Buffer(password).toString("base64"), @App.config.rsa_padding, 'base64')
					
					@Keys.insert null, row, (err, _result) =>
						if _result
							result =
								sender_id: req.query.sender_id

							if req.query.recipient_id
								result.recipient_id = req.query.recipient_id
							if req.query.group_id
								result.group_id = req.query.group_id
							
							result.key_encrypted = if isSender then row.senderkey else row.recipientkey
							@Packages.insert "package_#{packageToken}", result
							packageToken = dcrypt.rsa.encrypt(mePubKey, new Buffer(packageToken).toString("base64"), @App.config.rsa_padding, 'base64')
							@App.compressIfRequested req, res, {package_id_encrypted: packageToken}
						else
							return @App.sendError req, res, 400, "Error while generating key"

		@_getPubKey req.query.sender_id, (err, senderPubKey) =>
			if senderPubKey
				mePubKey = senderPubKey.pubkey
				getRecipientPubKey = (recipient_id, callback) =>
					@_getPubKey recipient_id, (err, recipientPubKey) =>
						if recipientPubKey.pubkey
							if callback then callback recipientPubKey, null
						else if !err
							return @App.sendError req, res, 400, "Invalid ids provided"
						else
							return @App.sendError req, res, 500, "Error while contacting Morse server"

				getGroupPubKey = (group_id, callback) =>
					@_getGroupPubKey group_id, (err, groupPubKey) =>
						if groupPubKey.pubkey
							if callback then callback null, groupPubKey
						else if !err
							return @App.sendError req, res, 400, "Invalid ids provided"
						else
							return @App.sendError req, res, 500, "Error while contacting Morse server"

				getMsgKey = (recipientPubKey, groupPubKey) =>
					#console.log "isSender: #{isSender}"
					if !recipientPubKey
						recipientPubKey = {}

					if !groupPubKey
						groupPubKey = {}

					#console.log senderPubKey
					#console.log recipientPubKey
					#console.log groupPubKey 

					if !isSender
						if req.query.recipient_id and recipientPubKey.user_id is req.query.recipient_id
							mePubKey = recipientPubKey.pubkey
						else
							getRecipientPubKey req.query.me, (me) =>
								mePubKey = me.pubkey
								retrieveMsgKey senderPubKey.pubkey, recipientPubKey.pubkey, groupPubKey.pubkey, mePubKey
							return

					retrieveMsgKey senderPubKey.pubkey, recipientPubKey.pubkey, groupPubKey.pubkey, mePubKey

				if req.query.recipient_id
					getRecipientPubKey req.query.recipient_id, getMsgKey
				else if req.query.group_id
					getGroupPubKey req.query.group_id, getMsgKey
			else
				return @App.sendError req, res, 400, "Invalid ids provided"
			

module.exports = Keys
