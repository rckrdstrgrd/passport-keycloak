var Config = require('keycloak-auth-utils').Config,
    GrantManager = require('keycloak-auth-utils').GrantManager,
    Keycloak = require('keycloak-connect'),
    uuid = require('uuid'),
    URL = require('url');



function Strategy(options, verify) {
    this.config = new Config(options);
    this.grantManager = new GrantManager(this.config);
    this.name = 'keycloak';
    this.verify = verify;
    this.
}

Strategy.SESSION_KEY = 'keycloak-token';

Strategy.prototype.authenticate = function(req, options) {
    var self = this;
    if (req.query && req.query.error) {
        return this.fail(req.query.error);
    }

    function verified(err, user, info) {
        if (err) {
            return self.error(err);
        }
        if (!user) {
            return self.fail(info);
        }
        self.success(user, info);
    }

    this.getGrant(req).then(grant => {
        self.verify(grant.access_token.content, verified);
    }).catch(() => {
        if (req.query.auth_callback) {
            var sessionId = req.session ? req.session.id : undefined;
            this.getGrantFromCode(req, req.query.code, sessionId).then(grant => {
                if (req.session) {
                    req.session[Strategy.SESSION_KEY] = grant.__raw;
                }
                self.redirect(cleanUrl(req));
            });
        } else {
            var redirectUrl = this.getRedirectUrl(req);
            if (req.session) {
                req.session.auth_redirect_uri = redirectUrl;
            }
            var loginURL = this.loginUrl(uuid.v4(), redirectUrl);
            this.redirect(loginURL);
        }
    });


};

Strategy.prototype.getGrantFromCode = function(req, code, sessionId) {
    return this.grantManager.obtainFromCode(req, code, sessionId)
        .then(grant => {
            return grant;
        });
};

Strategy.prototype.cleanUrl = function(req) {
    var urlObj = {
        pathname: req.path,
        query: req.query
    };
    delete urlObj.query.code;
    delete urlObj.query.auth_callback;
    delete urlObj.query.state;

    return URL.format(urlObj);
}

Strategy.prototype.getGrant = function(req) {
    var grantData = req.session[Strategy.SESSION_KEY];
    if (typeof grantData === 'string') {
        grantData = JSON.parse(grantData);
    }
    if (grantData && !grantData.error) {
        var grant = this.grantManager.createGrant(JSON.stringify(grantData));
        return this.grantManager.ensureFreshness(grant)
            .then(grant => {
                return grant;
            });
    }
    return Promise.reject();
};

Strategy.prototype.loginUrl = Keycloak.prototype.loginUrl;

Strategy.prototype.getRedirectUrl = function(req) {
    var host = req.hostname;
    var headerHost = req.headers.host.split(':');
    var port = headerHost[1] || '';
    var protocol = req.protocol;
    return protocol + '://' + host + (port === '' ? '' : ':' + port) + (req.originalUrl || req.url) + '?auth_callback=1';
};


exports = module.exports = Strategy;
exports.Strategy = Strategy;
