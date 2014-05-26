/**
 * Cas
 */
var url = require('url'),
  http = require('http'),
  https = require('https'),
  passport = require('passport')

  function Strategy(options, verify) {
    if (typeof options == 'function') {
      verify = options;
      options = {};
    }
    if (!verify) {
      throw new Error('cas authentication strategy requires a verify function');
    }

    this.ssoBase = options.ssoBaseURL;
    this.serverBaseURL = options.serverBaseURL;
    this.parsed = url.parse(this.ssoBase);
    if (this.parsed.protocol === 'http:') {
      this.client = http;
    } else {
      this.client = https;
    }

    passport.Strategy.call(this);

    this.name = 'cas';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
  }

Strategy.prototype.authenticate = function(req, options) {
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

  var ticket = req.param('ticket');
  if (!ticket) {
    var redirectURL = url.parse(this.ssoBase + '/login', true);
    var service = this.serverBaseURL + req.url;

    redirectURL.query.service = service;
    return this.redirect(url.format(redirectURL));
  }

  var resolvedURL = url.resolve(this.serverBaseURL, req.url);
  var parsedURL = url.parse(resolvedURL, true);
  delete parsedURL.query.ticket;
  delete parsedURL.search;
  var validateService = url.format(parsedURL);

  var self = this;

  var verified = function(err, user, info) {
    if (err) {
      return self.error(err);
    }
    if (!user) {
      return self.fail(info);
    }
    self.success(user, info);
  };

  var get = this.client.get({
    host: this.parsed.hostname,
    port: this.parsed.port,
    path: url.format({
      pathname: '/validate',
      query: {
        ticket: ticket,
        service: validateService
      }
    })
  }, function(response) {
    response.setEncoding('utf8');
    var body = '';
    response.on('data', function(chunk) {
      return body += chunk;
    });
    return response.on('end', function() {
      var lines = body.split('\n');
      if (lines.length >= 1) {
        if (lines[0] === 'no') {
          return self.fail(new Error('Authentication failed'));
        } else if (lines[0] === 'yes' && lines.length >= 2) {
          if (self._passReqToCallback) {
            self._verify(req, lines[1], verified);
          } else {
            self._verify(lines[1], verified);
          }
          return;
        }
      }
      return self.fail(new Error('The response from the server was bad'));
    });
  });

  get.on('error', function(e) {
    return self.fail(new Error(e));
  });
};


exports.Strategy = Strategy;
