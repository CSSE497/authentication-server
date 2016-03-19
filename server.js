const express = require('express');
const https = require('https');
const bodyParser = require('body-parser');
const session = require('express-session');
const promise = require('bluebird');
const pg = require('pg-promise')(
	{ promiseLib: promise }
);
const fs = require('fs');
const config = require('./config.json');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const url = require('url');
const querystring = require('querystring');
const database = pg(config.database);
const credentials = {
	key: fs.readFileSync(config.ssl.key).toString(),
	cert: fs.readFileSync(config.ssl.certificate).toString()
};
const crypto = require('crypto');
const util = require('util');
const ursa = require('ursa');
const jwtOptions = {
	audience: config.google.clientId,
	algorithms: ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
};
Object.assign = require('object-assign');

function httpsGet(url, done){
	https.get(url, function(res){
		var body = '';
		res.on('data', function(chunk){
			body += chunk;
		});
		res.on('end', function(){
			done(null, JSON.parse(body));
		});
		res.on('close',function(){
			done(true);
		});
	});
}

function getOpenIdConfig(done){
	httpsGet(config.google.openId, function(closed, res) {
		if(closed){
			console.warn('failed to get open id config');
			process.exit();
		}
		console.log(res);
		httpsGet(res.jwks_uri, function(closed, jwks){
			if(closed){
				console.warn('failed to get key');
				process.exit();
			}
			res.jwks = jwks;
			done(res);
		});
	});
}

function checkKey(jwk, header){
	return jwk.alg === header.alg && jwk.use === 'sig';
}

function verifyIdToken(jwks){
	return function(req, res, next){
		var rawToken = req.openid.rawToken;
		if(!rawToken){
			res.sendStatus(500);
			next(Error('id token missing'));
			return;
		}
		console.log(rawToken);
		var decoded = jwt.decode(rawToken, { complete: true });
		var token = decoded.payload;
		var header = decoded.header;
		for(var i = 0; i < jwks.length; ++i){
			var jwk = jwks[i];
			if(!checkKey(jwk, header)){
				continue;
			}
			var key = jwkToPem(jwk);
			console.log(key);
			try {
				jwt.verify(rawToken, key, jwtOptions)
			} catch(err) {
				continue;
			}
			console.log('VERIFIED');
			console.log(token);
			req.openid.token = token;
			next();
			return;
		}
		res.send(500,'unable to authenticate user');
		next(new jwt.JsonWebTokenError('invalid signature'));
	}
}

getOpenIdConfig(function(googleConfig){

	const redirect_uri = url.format({
		protocol: 'https',
		hostname: config.server.host,
		port: config.server.port,
		pathname: '/auth/google/return'
	});

	jwtOptions.issuer = googleConfig.issuer;
	server = express();
	server.use(session({
		saveUninitialized: false,
		resave: false,
		cookie: { secure: true },
		secret: config.session.secret
	}));

	server.use(bodyParser.json({limit:'50mb'}));
	server.use(bodyParser.urlencoded());

	server.get('/auth/google',
		function(req, res, next){
			if(!req.query.return_url){
				res.status(400).send('no return url specified');
				return;
			}
			if(!req.query.application){
				res.status(400).send('no application specified');
				return;
			}
			req.session.return_url = req.query.return_url;
			req.session.application = req.query.application;
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
							res.status(500).send('Internal Server Error');
							next(error);
							break;
					}
				});
		},
		function(req, res){
			var authUrl = url.parse(googleConfig.authorization_endpoint);
			authUrl.query = {
				redirect_uri: redirect_uri,
				response_type: 'code',
				scope: 'openid email',
				state: req.session.id,
				client_id: config.google.clientId
			};
			res.redirect(authUrl.format());
		}
	);

	server.get('/auth/google/return',
		function(req, res, next){
			if(req.session.id !== req.query.state){
				res.send(401, 'invalid session state');
				return;
			}
			if(req.query.error){
				console.warn(req.query.error);
				res.send(400, req.query.error);
				return;
			}
			if(!req.query.code){
				res.send(401, 'code parameter missing');
				return;
			}
			var body = querystring.stringify({
				code: req.query.code,
				client_id: config.google.clientId,
				client_secret: config.google.secret,
				redirect_uri: redirect_uri,
				grant_type: 'authorization_code'
			});

			var options = url.parse(googleConfig.token_endpoint);
			options.method = 'POST';
			options.headers = {
				'Content-Type': 'application/x-www-form-urlencoded'
			};

			var post = https.request(options, function(result){
				var data = '';
				result.on('data', function(chunk){
					data += chunk;
				});
				result.on('end', function(){
					req.openid = {
						rawToken: JSON.parse(data).id_token
					};
					next();
				});
				result.on('close', function(){
					res.sendStatus(500, 'Error getting tokens');
				});
			});

			post.on('error', function(e){
				res.send(500, 'Error getting tokens');
				throw e;
			});
			post.end(body);
		},
		verifyIdToken(googleConfig.jwks.keys),
		function(req, res){
			var token = req.openid.token;
			var email = token.email;
			var appId = req.session.application_id;
			database.none('insert into permission (email, application_id, permission) values ($1, $2, $3) on conflict do nothing',[email, appId, '[]'])
				.then(function(){
					res.redirect(req.session.url);
				}).catch(function(e){
					res.send(500);
					next(e);
				});
		}
	);

	server.post('/token/:token', function(req, res, next){
		var token = req.params.token || req.body.token;
		if(!token){
			res.send(400,'no auth token sent');
			return;
		}

		var decoded = jwt.decode(token, {complete: true});
		var payload = decoded.payload;
		var header = payload.header;
		if(header.alg == 'none'){
			res.send(401,'algorithm required');
			return;
		}
		for(field in ['exp','application_id','id']){
			if(payload[field] === undefined || payload[field] === null){
				res.send(400, 'auth token missing required field: ' + field);
				return;
			}
		}
		if(payload.nonce){
			if(payload.nonce !== req.body.nonce){
				res.send(401,'nonce mismatch');
				return;
			}
		}
		if(payload.exp < Math.floor(new Date() / 1000)){
			res.send(401,'auth token expired');
			return;	
		}
		database.one('select secret from application where application_id = $1',[application_id])
			.then(function(secret){
				jwt.verify(token, secret, function(err, data){
					if(err) {
						res.send(401,'id token expired');
					} else {
						req.token = data;
						next();
					}
				});
			})
			.catch(function(err){
				res.send(404, 'application: ' + application_id + ' not found');
			});
	}, function(req, res){
		var issuer = req.token.id_iss;
		var idToken = req.token.id;
		var permissions = req.token.permissions || [];
		var application_id = req.body.application_id;
		handleIdToken(req.token, req.token.refresh, function(err){
			if(err){
				res.send(400, err.message);
			}
		});
	});

	server.get('/:stuff',function(req,res){
		res.send('hello world: ' + req.params.stuff);

	});

	https.createServer(credentials, server).listen(config.server.port);
});

