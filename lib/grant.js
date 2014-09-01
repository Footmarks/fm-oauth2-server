
var auth = require('basic-auth'),
  error = require('./error'),
  runner = require('./runner'),
  token = require('./token');

module.exports = Grant;

var fns = [
  extractCredentials,
  checkCredentials,
  checkGrantType,
  generateAccessToken,
  saveAccessToken,
  sendResponse
];

function Grant(config, req, res, next) {
    this.config = config;
    this.model = config.model;
    this.now = new Date();
    this.req = req;
    this.res = res;

    runner(fns, this, next);
}

function extractCredentials(done) {
    // Only POST via application/x-www-form-urlencoded is acceptable
    if (this.req.method !== 'POST' ||
        !this.req.is('application/x-www-form-urlencoded')) {
        return done(error('invalid_request',
          'Method must be POST with application/x-www-form-urlencoded encoding'));
    }

    // Grant type
    this.grantType = this.req.body && this.req.body.grant_type ? this.req.body.grant_type : undefined;
    if (!this.grantType ) {
        return done(error('invalid_request',
          'Invalid or missing grant_type parameter'));
    }

    if (this.grantType === 'app_credentials') {
        this.app = appCredsFromBody(this.req);
        if (!this.app.appKey) {
            return done(error('invalid_app',
              'Invalid app_key parameter'));
        } else if (!this.app.appSecret) {
            return done(error('invalid_app', 'Missing app_secret parameter'));
        } else if (!this.app.deviceId) {
            return done(error('invalid_app', 'Missing device_id parameter'));
        }

        done();
    }
    else {
        this.client = credsFromBasic(this.req) || clientCredsFromBody(this.req);

        if (!this.client.clientSecret) {
            return done(error('invalid_client', 'Missing client_secret parameter'));
        }

        done();
    }
}

function Client(id, secret) {
    this.clientId = id;
    this.clientSecret = secret;
}

function App(key, secret, device) {
    this.appKey = key;
    this.appSecret = secret;
    this.deviceId = device;
}
function App_more(id, client) {
    this.id = id;
    this.clientId = client;
}

function credsFromBasic(req) {
    var user = auth(req);

    if (!user) return false;

    return new Client(user.name, user.pass);
}

function clientCredsFromBody(req) {
    return new Client(req.body.client_id, req.body.client_secret);
}

function appCredsFromBody(req) {
    return new App(req.body.app_key, req.body.app_secret, req.body.device_id);
}

function checkCredentials(done) {
    var self = this;
    if (this.client) {
        this.model.getCompany(this.client.clientId, this.client.clientSecret,
            function (err, client) {
                if (err) return done(error('server_error', false, err));

                if (!client) {
                    return done(error('invalid_client', 'Client credentials are invalid'));
                }
                done();
            });
    } else if (this.app) {
        var appKey = this.app.appKey;
        var appSecret = this.app.appSecret;
        this.model.getApp(appKey, appSecret, function (err, app) {
            if (err) return done(error('server_error', false, err));

            if (!app) {
                return done(error('invalid_app', 'App credentials are invalid'));
            }
            self.app_more = new App_more(app._id, app.company);
            done();
        });
    }

}

function checkGrantType(done) {
    switch (this.grantType) {
        case 'password':
            return usePasswordGrant.call(this, done);
        case 'app_credentials':
            return useAppCredentialsGrant.call(this, done);
        default:
            done(error('invalid_request',
              'Invalid grant_type parameter or parameter missing'));
    }
}

function usePasswordGrant(done) {
    // User credentials
    var uname = this.req.body.username,
      pword = this.req.body.password;
    if (!uname || !pword) {
        return done(error('invalid_client',
          'Missing parameters. "username" and "password" are required'));
    }

    var self = this;
    this.model.getAdminUser(uname, pword, function (err, user) {
        if (err) return done(error('server_error', false, err));
        else if (!user) {
            return done(error('invalid_grant', 'User credentials are invalid'));
        }
        else {
            self.user = user;
            done();
        }
    });
}

function useAppCredentialsGrant(done) {
    // App credentials
    var key = this.app.appKey,
      secret = this.app.appSecret,
      device = this.app.deviceId,
      id = this.app_more.id,
      client = this.app_more.clientId;

    if (!key || !secret || !device || !id || !client) {
        console.log('before invalid app');
        return done(error('invalid_app',
          'Missing parameters. "app_key" and "app_secret" and "device_id" are required'));
    }

    var self = this;
    this.model.getUser({ deviceId: device, appId: id, companyId: client },
        function (err, user) {
            console.log(user);
            if (err) return done(error('server_error', false, err));
            if (!user) {
                return done(error('invalid_grant', 'App credentials are invalid'));
            }

            self.user = user;
            done();
        });
}

function generateAccessToken(done) {
    var self = this;
    token(this, 'accessToken', function (err, token) {
        self.accessToken = token;
        done(err);
    });
}

function saveAccessToken(done) {
    var accessToken = this.accessToken;

    console.log('saveaccesstoken');
    // Object idicates a reissue
    if (typeof accessToken === 'object' && accessToken.accessToken) {
        this.accessToken = accessToken.accessToken;
        return done();
    }

    var expires = null;
    if (this.config.accessTokenLifetime !== null) {
        expires = new Date(this.now);
        expires.setSeconds(expires.getSeconds() + this.config.accessTokenLifetime);
    }

    if (this.client) {
        this.model.saveAccessToken({ accessToken: accessToken, companyId: this.client.clientId, expires: expires, adminUser: this.user, grantType: this.grantType },
            function (err) {
                console.log('before error');
                if (err) return done(error('server_error', false, err));
                done();
            });
    } else if (this.app) {
        this.model.saveAccessToken({ accessToken: accessToken, companyId: this.app_more.clientId, expires: expires, user: this.user, grantType: this.grantType },
            function (err) {
                if (err) return done(error('server_error', false, err));
                done();
            });
    }

}

function sendResponse(done) {
    var response = {
        token_type: 'bearer',
        access_token: this.accessToken
    };

    if (this.config.accessTokenLifetime !== null) {
        response.expires_in = this.config.accessTokenLifetime;
    }

    this.res.jsonp(response);

    if (this.config.continueAfterResponse)
        done();
}
