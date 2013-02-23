uuid = require "node-uuid"
crypto = require "crypto"
RSA = require "nrsa"

class Keys
	constructor: (@App) ->
		@Keys = new (require "./keys") @App
		@Packages = new (require "./packages") @App

		@App.server.get "/requestKey", @getKey
		@App.server.get "/getPackage", @getPackage
		@App.server.get "/createKey", @createKey

	_generateRandomPassword: () =>
		password = ""
		random = crypto.randomBytes(@App.config.password_length)
		for buf in random
			c = buf # the character in range 0 to 255
			c2 = Math.floor(c / 2.74) # transform to range 0 - 93 and round down
			c3 = c2 + 33 # ASCII to range from 33 to 126
			# now convert the transformed character code to its string
			# value and append to the verification code
			password += String.fromCharCode c3

		return password
		#return dcrypt.random.randomBytes(@App.config.password_length).toString("base64")

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

	# GET /getPackage
	# params (query):
	# 	id: id of package to retrieve
	#
	# notes: key_encrypted returned will need to be decrypted with the requester private key

	getPackage: (req, res, next) =>
		if req.query.id
			@Packages.findOne "package_#{req.query.id}", (err, reply) =>
				if reply
					@Packages.del "package_#{req.query.id}"
					delete reply._rev
					return @App.compressIfRequested req, res, reply
				else
					return @App.sendError req, res, 400, "Invalid package token provided"
		else
			return @App.sendError req, res, 400, "Invalid package token provided"

	# GET /requestKey
	# params (query):
	# 	id: id of key to retrieve
	#	me: hashed id of the user (can be sender, recipient or group)
	#
	# notes: package_id_encrypted returned will need to be decrypted with the requester private key

	getKey: (req, res, next) =>
		if !req.query.id
			return @App.sendError req, res, 400, "Invalid id provided"

		if !req.query.me
			return @App.sendError req, res, 400, "Invalid user provided"

		packageToken = @_generateUniqueToken()

		retrieveMsgKey = (_id, me, pubkey) =>
			@Keys.findOne _id, (err, data) =>
				if data and (data.sender_id is me or data.recipient_id is me or data.group_id is me)
					result =
						id: data._id
						sender_id: data.sender_id
					
					if data.recipient_id
						result.recipient_id = data.recipient_id
					if data.group_id
						result.group_id = data.group_id

					if data.sender_id is me
						result.key_encrypted = data.senderkey
					else
						result.key_encrypted = data.recipientkey

					result.status = data.status

					@Packages.insert "package_#{packageToken}", result
					keypair = RSA.createRsaKeypair
						publicKey: pubkey.pubkey
						padding: @App.config.rsa_padding
					packageToken = keypair.encrypt new Buffer(packageToken).toString("base64"), "utf8", "base64"
					return @App.compressIfRequested req, res, {package_id_encrypted: packageToken}
				else if err
					return @App.sendError req, res, 500, "Error generating key request"
				else
					return @App.sendError req, res, 404, "Key not found"

		getUserPubKey = (user_id, callback) =>
			@_getPubKey user_id, (err, userPubKey) =>
				if userPubKey.pubkey
					if callback then callback userPubKey, null
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

		getMsgKey = (pubkey) =>
			retrieveMsgKey req.query.id, req.query.me, pubkey

		if req.query.is_group
			getGroupPubKey req.query.me, getMsgKey
		else
			getUserPubKey req.query.me, getMsgKey

	# GET /createKey
	# params (query):
	# 	sender_id: the hashed sender id
	#	recipient_id: the hashed recipient_id
	#	(or) group_id: the hashed group_id
	#	me: the hashed id of requester (need to be one of the above)
	#
	# notes: package_id_encrypted returned will need to be decrypted with the requester private key

	createKey: (req, res, next) =>
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

			password = @_generateRandomPassword()
			
			row = @Keys.schema
			row.sender_id = req.query.sender_id
			
			if req.query.recipient_id
				row.recipient_id = req.query.recipient_id
			if req.query.group_id
				row.group_id = req.query.group_id

			keypair = RSA.createRsaKeypair
				publicKey: senderPubKey
				padding: @App.config.rsa_padding
			row.senderkey = keypair.encrypt new Buffer(password).toString("base64"), "utf8", "base64"
			if recipientPubKey
				keypair = RSA.createRsaKeypair
					publicKey: recipientPubKey
					padding: @App.config.rsa_padding
				row.recipientkey = keypair.encrypt new Buffer(password).toString("base64"), "utf8", "base64"
			else if groupPubKey
				keypair = RSA.createRsaKeypair
					publicKey: groupPubKey
					padding: @App.config.rsa_padding
				row.recipientkey = keypair.encrypt new Buffer(password).toString("base64"), "utf8", "base64"
			
			@Keys.insert null, row, (err, _result) =>
				if _result
					result =
						keyid: _result.id
						sender_id: req.query.sender_id

					if req.query.recipient_id
						result.recipient_id = req.query.recipient_id
					if req.query.group_id
						result.group_id = req.query.group_id
					
					result.key_encrypted = if isSender then row.senderkey else row.recipientkey
					@Packages.insert "package_#{packageToken}", result
					keypair = RSA.createRsaKeypair
						publicKey: mePubKey
						padding: @App.config.rsa_padding
					packageToken = keypair.encrypt new Buffer(packageToken).toString("base64"), "utf8", "base64"
					return @App.compressIfRequested req, res, {package_id_encrypted: packageToken}
				else
					return @App.sendError req, res, 500, "Error while generating key"

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
