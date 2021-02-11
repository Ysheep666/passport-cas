/**
 * Cas
 */
var _ = require('underscore'),
    http = require('http'),
    https = require('https'),
    parseString = require('xml2js').parseString,
    processors = require('xml2js/lib/processors'),
    passport = require('passport'),
    uuid = require('uuid/v4'),
    util = require('util');

function Strategy(options, verify) {
    if (typeof options == 'function') {
        verify = options;
        options = {};
    }
    if (!verify) {
        throw new Error('cas authentication strategy requires a verify function');
    }
    this.version = options.version || "CAS1.0";
    this.ssoBase = options.ssoBaseURL;
    this.serverBaseURL = options.serverBaseURL;
    this.validateURL = options.validateURL;
    this.serviceURL = options.serviceURL;
    this.useSaml = options.useSaml || false;
    this.parsed = new URL(this.ssoBase);
    if (this.parsed.protocol === 'http:') {
        this.client = http;
    } else {
        this.client = https;
    }

    passport.Strategy.call(this);


    this.name = 'cas';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;

    var xmlParseOpts = {
        'trim': true,
        'normalize': true,
        'explicitArray': false,
        'tagNameProcessors': [processors.normalize, processors.stripPrefix]
    };

    var self = this;
    switch (this.version) {
        case "CAS1.0":
            this._validateUri = "/validate";
            this._validate = function (req, body, verified) {
                var lines = body.split('\n');
                if (lines.length >= 1) {
                    if (lines[0] === 'no') {
                        return verified(new Error('Authentication failed'));
                    } else if (lines[0] === 'yes' && lines.length >= 2) {
                        if (self._passReqToCallback) {
                            self._verify(req, lines[1], verified);
                        } else {
                            self._verify(lines[1], verified);
                        }
                        return;
                    }
                }
                return verified(new Error('The response from the server was bad'));
            };
            break;
        case "CAS3.0":
            if (this.useSaml) {
                this._validateUri = "/samlValidate";
                this._validate = function (req, body, verified) {
                    parseString(body, xmlParseOpts, function (err, result) {
                        if (err) {
                            return verified(new Error('The response from the server was bad'));
                        }
                        try {
                            var response = result.envelope.body.response;
                            var success = response.status.statuscode['$'].Value.match(/Success$/);
                            if (success) {
                                var attributes = {};
                                _.each(response.assertion.attributestatement.attribute, function (attribute) {
                                    attributes[attribute['$'].AttributeName.toLowerCase()] = attribute.attributevalue;
                                });
                                var profile = {
                                    'user': response.assertion.authenticationstatement.subject.nameidentifier,
                                    'attributes': attributes
                                };
                                if (self._passReqToCallback) {
                                    self._verify(req, profile, verified);
                                } else {
                                    self._verify(profile, verified);
                                }
                                return;
                            }
                            return verified(new Error('Authentication failed'));
                        } catch (e) {
                            return verified(new Error('Authentication failed'));
                        }
                    });
                };
            } else {
                this._validateUri = "/p3/serviceValidate";
                this._validate = function (req, body, verified) {
                    parseString(body, xmlParseOpts, function (err, result) {
                        if (err) {
                            return verified(new Error('The response from the server was bad'));
                        }
                        try {
                            if (result.serviceresponse.authenticationfailure) {
                                return verified(new Error('Authentication failed ' + result.serviceresponse.authenticationfailure.$.code));
                            }
                            var success = result.serviceresponse.authenticationsuccess;
                            if (success) {
                                if (self._passReqToCallback) {
                                    self._verify(req, success, verified);
                                } else {
                                    self._verify(success, verified);
                                }
                                return;
                            }
                            return verified(new Error('Authentication failed'));

                        } catch (e) {
                            return verified(new Error('Authentication failed'));
                        }
                    });
                };
            }
            break;
        default:
            throw new Error('unsupported version ' + this.version);
    }
}

Strategy.prototype.service = function (req) {
    var serviceURL = this.serviceURL || req.originalUrl;
    var urlObject = new URL(serviceURL, this.serverBaseURL);
    urlObject.searchParams.delete("ticket");
    return urlObject.toString();
};

Strategy.prototype.authenticate = function (req, options) {
    options = options || {};

    // CAS Logout flow as described in
    // https://wiki.jasig.org/display/CAS/Proposal%3A+Front-Channel+Single+Sign-Out var relayState = req.query.RelayState;
    var relayState = req.query.RelayState;
    if (relayState) {
        // logout locally
        req.logout();
        return this.redirect(this.ssoBase + '/logout?_eventId=next&RelayState=' +
            relayState);
    }

    var service = this.service(req);

    var ticket = req.query.ticket;
    if (!ticket) {
        var redirectURL = new URL(this.ssoBase + '/login');

        redirectURL.searchParams.set("service", service);
        // copy loginParams in login query
        for (var property in options.loginParams) {
            var loginParam = options.loginParams[property];
            if (loginParam) {
                redirectURL.searchParams.set(property, loginParam);
            }
        }
        return this.redirect(redirectURL.toString());
    }

    var self = this;
    var verified = function (err, user, info) {
        if (err) {
            return self.error(err);
        }
        if (!user) {
            return self.fail(info);
        }
        self.success(user, info);
    };
    var _validateUri = this.validateURL || this._validateUri;

    var _handleResponse = function (response) {
        response.setEncoding('utf8');
        var body = '';
        response.on('data', function (chunk) {
            return body += chunk;
        });
        return response.on('end', function () {
            return self._validate(req, body, verified);
        });
    };

    let target = new URL(_validateUri, this.parsed);
    if (this.useSaml) {
        var requestId = uuid.v4();
        var issueInstant = new Date().toISOString();
        var soapEnvelope = util.format('<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s"><samlp:AssertionArtifact>%s</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>', requestId, issueInstant, ticket);
        target.searchParams.set("TARGET", service);
        var request = this.client.request(target, {
            method: 'POST',
        }, _handleResponse);

        request.on('error', function (e) {
            return self.fail(new Error(e));
        });
        request.write(soapEnvelope);
        request.end();
    } else {
        target.searchParams.set("ticket", ticket);
        target.searchParams.set("service", service);
        var get = this.client.get(target, _handleResponse);

        get.on('error', function (e) {
            if (e.errno == "EHOSTUNREACH") {
                return self.fail(new Error(e), 504);
            }
            return self.fail(new Error(e));
        });
    }
};


exports.Strategy = Strategy;
