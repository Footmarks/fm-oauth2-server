
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
    if (!this.grantType) {
        return done(error('invalid_request',
          'Invalid or missing grant_type parameter'));
    }

    if (this.grantType === 'app_credentials') {
        this.app = appCredsFromBasic(this.req) || appCredsFromBody(this.req);
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
        this.company = credsFromBasic(this.req);

        if (!this.company.secret) {
            return done(error('invalid_company', 'Invalid auth header parameter'));
        }

        done();
    }
}

function Company(key, secret) {
    this.key = key;
    this.secret = secret;
}

function App(key, secret, device) {
    this.appKey = key;
    this.appSecret = secret;
    this.deviceId = device;
}
function App_more(id, company) {
    this.id = id;
    this.companyId = company;
}

function credsFromBasic(req) {
    var user = auth(req);
    if (!user) return false;
    return new Company(user.name, user.pass);
}

function appCredsFromBasic(req) {
    var user = auth(req);
    if (!user) return false;
    return new App(user.name, user.pass, req.body.device_id);
}

function appCredsFromBody(req) {
    return new App(req.body.app_key, req.body.app_secret, req.body.device_id);
}

function checkCredentials(done) {
    var self = this;
    if (this.company) {
        this.model.getCompany(this.company.key, this.company.secret,
            function (err, company) {
                if (err) return done(error('server_error', false, err));

                if (!company) {
                    return done(error('invalid_company', 'Company credentials are invalid'));
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
        return done(error('invalid_company',
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
      company = this.app_more.companyId;

    if (!key || !secret || !device || !id || !company) {
        console.log('before invalid app');
        return done(error('invalid_app',
          'Missing parameters. "app_key" and "app_secret" and "device_id" are required'));
    }

    var self = this;
    this.model.getUser({ deviceId: device, appId: id, companyId: company },
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

    if (this.company) {
        this.model.saveAccessToken({ accessToken: accessToken, companyId: this.user.company, expires: expires, user: this.user, grantType: this.grantType },
            function (err) {
                if (err) return done(error('server_error', false, err));
                done();
            });
    } else if (this.app) {
        this.model.saveAccessToken({ accessToken: accessToken, companyId: this.app_more.companyId, expires: expires, user: this.user, grantType: this.grantType },
            function (err) {
                if (err) return done(error('server_error', false, err));
                done();
            });
    }

}

function sendResponse(done) {
    var response = {
        grantType: this.grantType,
        accessToken: this.accessToken
    };

    if (this.config.accessTokenLifetime !== null) {
        response.expires_in = this.config.accessTokenLifetime;
    }

    this.res.jsonp(response);

    if (this.config.continueAfterResponse)
        done();
}
