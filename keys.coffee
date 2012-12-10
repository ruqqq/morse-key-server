class Keys extends (require "./model.couchdb.coffee")
	table_name: "keys"
	schema:
		sender_id: null
		recipient_id: null
		group_id: null
		senderkey: null
		recipientkey: null
		status: 1
		created: null
		modified: null

	constructor: (@App) ->
		super @App

		# init views if not existing
		key = "_design/keys"
		@findOne key, (err, data) =>
			if !err and !data
				view = 
					language: "javascript"
					views:
						"sender_id-recipient_id":
							map: "function(doc) {\n  if (doc.recipient_id) emit(doc.sender_id + \"-\" + doc.recipient_id, doc);\n}"
						"sender_id-group_id": 
							map: "function(doc) {\n  if (doc.group_id) emit(doc.sender_id + \"-\" + doc.group_id, doc);\n}"
				@insert key, view, (err, result) =>
					if !err
						console.log "[DB][Keys] Views initialized."
					else
						console.log "[DB][Keys] Failed to initialize Views. App might not work correctly."
						console.log err

	findOneWith: (conditions, callback) =>
		viewBy = ""
		params = {}
		if conditions.recipient_id
			viewBy = "sender_id-recipient_id"
			params.key = "#{conditions.sender_id}-#{conditions.recipient_id}"
		else if conditions.group_id
			viewBy = "sender_id-group_id"
			params.key = "#{conditions.sender_id}-#{conditions.group_id}"

		if !params.key or !viewBy
			if callback then callback "Error: Invalid conditions provided", null
			return

		@db.view @table_name, viewBy, params, (err, body, header) =>
			if !err and body.total_rows > 0
				if callback then callback null, body.rows[0].value
			else if (err and err.status_code is 404) or body.total_rows < 1
				if callback then callback null, null
			else
				if callback then callback "#{err.error}: #{err.reason}", null

module.exports = Keys