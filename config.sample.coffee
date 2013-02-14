config = 
	# this should be morse server url
	mainURL: "http://jp1.ruqqq.sg:8030"
	# this is your couchdb config. by default your databases would be named:
	# - morse-key-server-keys
	# - morse-key-server-packages
	couchdb:
		host: "sample.cloudant.com",
		user: ""
		password: ""
		database_prefix: "morse-key-server-"
	# port number to run the server on
	port: 80
	# force disable gzip and deflate support
	force_disable_compression: false
	# the debug msg switch
	debug: false
	# RSA padding method to use
	# !!! THIS SHOULDN'T BE CHANGED UNLESS MORSE SERVER CHANGE !!!
	rsa_padding: "pkcs1" # oaep
	# Key/Password length to generate
	password_length: 32

module.exports = config