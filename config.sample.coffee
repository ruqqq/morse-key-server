config = 
	mainURL: "http://jp1.ruqqq.sg:8030"
	couchdb:
		host: "sample.cloudant.com",
		user: ""
		password: ""
		database_prefix: "morse-key-server-"
	port: 80
	force_disable_compression: false
	debug: false
	rsa_padding: "RSA_PKCS1_PADDING" # RSA_PKCS1_OAEP_PADDING
	password_length: 24

module.exports = config