const express = require('express');
const https = require('https');
const http = require('http');
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
const jwtOptions = {
	audience: config.google.clientId,
	algorithms: ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
};
const rsa = {
	private: fs.readFileSync(config.jwtCreation.key.private),
	public: fs.readFileSync(config.jwtCreation.key.public)
};

Error.stackTraceLimit = Infinity;

function httpsGet(url, done){
	https.get(url, function(res){
		var body = '';
		res.on('data', function(chunk){
			body += chunk;
		});
		res.on('end', function(){
			done(false, JSON.parse(body));
		});
		res.on('close',function(){
			done(new Error('Failed to load resource: ' + url));
		});
	});
}

function getKeys(gConf, done){
	httpsGet('https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys', function(idError, idKeys){
		if(idError){
			console.warn('failed to get google openid key');
			done(idError);
			return;
		}
		httpsGet(gConf.jwks_uri, function(jwkError, jwks){
			if(jwkError){
				console.warn('failed to get google openid key');
				done(jwlError);
			}
			gConf.jwks = jwks;
			Object.keys(idKeys).forEach(function(k){
				jwks.keys.push(idKeys[k]);
			});
			console.log('KEYS: ' + JSON.stringify(gConf.jwks.keys));
			done(false, gConf);
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
		getKeys(res, done);
	});
}

function verifyIdToken(gConf, options){
	return function(req, res, next){
		var rawToken = req.openid.rawToken;
		if(!rawToken){
			res.send(400, 'missing id token');
			next(Error('id token missing'));
			return;
		}
		if(!options){
			options = jwtOptions;
		}
		console.log(rawToken);
		var decoded = jwt.decode(rawToken, { complete: true });
		var token = decoded.payload;
		var header = decoded.header;
		function verify(){
			var jwks = gConf.jwks.keys;
			for(var i = 0; i < jwks.length; ++i){
				var jwk = jwks[i];
				var key = (typeof jwk === 'string') ? jwk : jwkToPem(jwk);
				console.log(key);
				try {
					jwt.verify(rawToken, key, options)
				} catch(err) {
					if(err instanceof jwt.TokenExpiredError){
						res.send(400, 'token expired');
						console.log('token expired');
						return true;
					}
					if(err instanceof jwt.JsonWebTokenError){
						console.log(err);
						continue;
					} else {
						res.send(400, err.message);
						next(err);
						return true;
					}
				}
				console.log('VERIFIED');
				console.log(token);
				req.openid.token = token;
				next();
				return true;
			}
			return false;
		}
		if(verify()){
			return;
		}
		console.log('failed to verify signature, refreshing keys');
		getKeys(gConf, function(closed){
			if(closed){
				res.send(400,'failed to verify token');
				next(new jwt.JsonWebTokenError('failed to refresh google key'));
				return;
			}
			if(verify()){
				return;
			}
			res.send(400,'failed to verify token');
			next(new jwt.JsonWebTokenError('failed to verify token'));
		});
	}
}

getOpenIdConfig(function(googleConfErr, googleConfig){
	if(googleConfErr){
		throw googleConfErr;
	}

	const connection = [
		function(req, res, next){ // extract and authenticate token
			console.log('connection request: ' + JSON.stringify(req.query));
			res.header('Access-Control-Allow-Origin','*');
			if(req.query.token){
				var rawToken = req.query.token;
				var token = jwt.decode(rawToken);
				if(token.aud !== 'https://auth.thepathfinder.xyz'){
					res.send(401, 'token requires aud = "https://auth.thepathfinder.xyz"');
					return;
				}
				database.one('select name, key from application where id = $1',[token.iss])
					.then(function(key){
						try {
							jwt.verify(rawToken, key, {algorithms: ["RS256"]});
						} catch(e){
							next(e);
							res.send(401, e.message)
							return;
						}
						if(token.expires < Date.now() / 1000){
							next(jwt.JsonWebTokenError('Token Expired'));
							res.send(401, 'token expired');
							return;
						}
						req.pathfinder = {
							sub:token.sub,
							email:token.email,
							aud:'https://api.thepathfinder.xyz',
							appId:token.iss,
							status:'Authenticated',
							iss:'https://auth.thepathfinder.xyz'
						};
						next();
					})
					.catch(function(e){
						next(e);
						res.sendStatus(500);
					});
			} else if(req.query.id_token){
				var token = jwt.decode(req.query.id_token);
				var appId = req.query.application_id;
				var connectionId = req.query.connection_id;
				var email = token.email;
				console.log('Receive id token: '+req.query.id_token);
				if(!appId){
					res.send(400, 'application_id required');
					return;
				}
				if(!connectionId){
					res.send(400, 'connection_id required');
					return;
				}
				if(token.iss === googleConfig.issuer || token.iss === 'accounts.google.com' || true){
					var connection = req.query.connection
					req.openid = {
						rawToken: req.query.id_token
					};
					var options = {algorithms: jwtOptions.algorithms};
					verifyIdToken(googleConfig, options)(req,res,function(err){
						if(err){
							next(err);
							res.send(400, 'could not verify id token: '+ err.message);
							return;
						}
						console.log('google id token verified');
						req.pathfinder = {
							sub:connectionId,
							email:email,
							aud:'https://api.thepathfinder.xyz',
							appId:appId,
							status:'Authenticated',
							iss:'https://auth.thepathfinder.xyz'
						};
						next()
					});
				} else {
					res.send(400, 'invalid issuer for id token: ' + token.iss);
					console.log('invalid issuer for id token: ' + token.iss);
				}
			} else {
				res.send(400, 'No id token sent');
				console.log('No id token sent');
			}
		}, function(req, res, next){ // get permissions
			var pf = req.pathfinder;
			var email = pf.email;
			var appId = pf.appId
			database.one('select permissions from permission where email=$1 and application_id=$2;',[email, appId])
				.then(function(data){
					req.pathfinder.permissions = data.permissions;
					next();
				})
				.catch(function(e){
					if(e instanceof pg.QueryResultError){
						res.send(404, 'user not found');
						console.log('user not found:' + email);
					} else {
						res.send(500,'Error reading database for permissions with email: ' + email);
						next(e);
					}
				});
		}, function(req, res, next){ // assemble and save token
			var token = req.pathfinder;
			var tokenStr;
			try {
				tokenStr = jwt.sign(token, rsa.private, config.jwtCreation);
			} catch(e){
				next(e);
				res.send(500, 'Internal Server Error');
				return;
			}

			database.none(
				'insert into connection (id, token) values ($1, $2);',
				[token.sub, tokenStr]
			).then(function(){
				res.sendStatus(204);
			}).catch(function(e){
				if(e.toString().indexOf('error: duplicate key value violates unique constraint') !== -1) { // this is a generic Error so we need to check the message
					database.none(
						'update connection set token=$2 where id=$1;',
						[token.sub, tokenStr]
					).then(function(){
						res.sendStatus(204);
					}).catch(function(e){
						next(e);
						res.sendStatus(500);
					});
				} else {
					next(e);
					res.sendStatus(500);
				}
			});
		}
	];


	const redirect_uri = url.format({
		protocol: 'https',
		hostname: config.server.host,
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
			req.session.return_token = req.query.return_token;
			req.session.url_encode = req.query.url_encode;
			if(!(req.session.return_token || req.query.return_url)){
				res.status(400).send('no return url specified');
				return;
			}
			req.session.return_url = req.query.return_url;
			req.session.application = req.query.application;
			if(req.query.application){
				database.one("select id from application where id = $1",[req.query.application])
					.then(function(data){
						next();
					})
					.catch(function(error){
						switch(error.name){
							case 'QueryResultError':
								res.send(404,
									'no application with id: ' + req.query.application
								);
								break;
							default:
								res.statusStatus(500);
								next(error);
								break;
						}
					});
			} else {
				next();
			}
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
		verifyIdToken(googleConfig),
		function(req, res, next){
			var token = req.openid.token;
			var email = token.email;
			var appId = req.session.application;
			if(appId){
				database.none('insert into permission (email, application_id, permissions) values ($1, $2, $3);',[email, appId, '{}'])
					.then(next).catch(function(e){
						if(e.toString().indexOf('error: duplicate key value violates unique constraint') !== -1) { // this is a generic Error so we need to check the message
							next()
						} else {
							res.sendStatus(500);
							next(e);
						}
					});
			} else {
				next();
			}
		}, function(req, res, next){
			if(req.session.return_token){
				if(req.session.url_encode){
					res.send(encodeURIComponent(req.openid.rawToken));
				} else {
					res.send(req.openid.rawToken);
				}
			} else {
				var obj = url.parse(req.session.return_url);
				obj.query = obj.query || {};
				obj.query.id_token = req.openid.rawToken;
				res.redirect(url.format(obj));
			}
		}
	);

	server.get('/connection', function(req, res, next){
		if(config.apiServer.address && req.connection.remoteAddress !== config.apiServer.address){
			res.sendStatus(401);
			return;
		}
		var connectionId = req.query.connection_id;
		if(!connectionId){
			res.send(400, 'connection_id parameter not set');
		}
		database.one('delete from connection where id = $1 returning token;',[connectionId])
			.then(function(data){
				var jwt = new Buffer(data.token).toString('utf8'); 
				console.log('sending jwt');
				console.log(jwt);
				res.send(jwt);
			})
			.catch(function(e){
				next(e);
				res.sendStatus(500);
			});
	});

	server.post('/connection', connection);

	server.get('/certificate', function(req, res){
		res.set('Content-Type','text/plain');
		res.send(rsa.public);
	});

	server.get('/:stuff',function(req,res){
		res.sendStatus(404);

	});

	http.createServer(server).listen(config.server.port);
});

