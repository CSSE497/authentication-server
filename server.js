const express = require('express');
const https = require('https');
const bodyParser = require('body-parser');
const passport = require('passport');
const session = require('passport-session');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const promise = require('bluebird');
const pg = require('pg-promise')(
	{ promiseLib: promise }
);
const config = require('./config.json');
const jwt = require('jsonwebtoken');
const url = require('url');
const database = pg(config.database);
var googleKey = null;

passport.use(new GoogleStrategy({
		clientID: config.google.clientId,
		clientSecret: config.google.secret,
		callbackURL: url.resolve(config.server.url,'auth/google/return'),
		passReqToCallback : true
	},
	function(req, accessToken, refreshToken, profile, done){
		done(null, profile);
	}
));

server = express();

server.use(passport.initialize());

server.use(bodyParser.json({limit:'50mb'}));
server.use(bodyParser.urlencoded());

function getGooglePublicKey(done){
	https.get('https://www.googleapis.com/oauth2/v1/certs', function(res) {
		var body = '';
		res.on('data',function(chunk){
			body += chunk;
		});
		res.on('end',function(){
			var keyJson = JSON.parse(body);
			console.log('GOOGLE PEM: ' + JSON.stringify(keyJson));
			done(keyJson)
		});
		res.on('close',function(){
			console.warn('failed to get google oauth certs, retrying');
			setTimeout(function(){getGooglePublicKey(done)},0);
		});
	});
}

server.get('/auth',
	function(req, res, next){
		if(!req.query.return_url){
			res.status(400).send('no return url specified');
			return;
		}
		if(!req.query.application){
			res.status(400).send('no application specified');
			return;
		}
		database.one("select id from application where id = $1",[req.query.application])
			.then(function(data){
				next();
			})
			.catch(function(error){
				switch(error.name){
					case 'QueryResultError':
						res.status(404).send(
							'no application with id: ' + req.query.application
						);
						break;
					default:
						console.log('ERROR');
						res.status(500).send('Internal Server Error');
						console.error(error);
						break;
				}
			});
	},
	passport.authenticate('google', {
		scope: ['https://www.googleapis.com/auth/userinfo.profile']
	})
);

server.get('/auth/google/return',
	function(req,res,next){
		console.log('RECEIVED RETURN');
		next();
	},
	passport.authenticate('google'),
	function(req, res){
		console.log('RETURN');
		//console.log('RETURN');
		//console.log(JSON.stringify(req.query));
		//console.log(JSON.stringify(req.user));
		// redirect to redirect_url with key pair and profile
		res.send('RETURN');
	}
);

server.get('/:stuff',function(req,res){
	res.send('hello world: ' + req.params.stuff);

});

server.post('/',function(req,res){
	// verify user token
	// var token = req.param('idToken');
	// jwt.verify
	// extract user id
	// generate keys
	// put in database
	// respond with public key
});

getGooglePublicKey(function(key){
	googleKey = key;
	server.listen(config.server.port);
});

