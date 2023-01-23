'use strict';

const request = require('postman-request');
const _ = require('lodash');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;

const MAX_DOMAIN_LABEL_LENGTH = 63;
const MAX_ENTITY_LENGTH = 100;
const MAX_PARALLEL_LOOKUPS = 10;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _setupRegexBlocklists(options) {
  if (options.domainBlocklistRegex !== previousDomainRegexAsString && options.domainBlocklistRegex.length === 0) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug({ domainBlocklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blocklist Regex');
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }

  if (options.ipBlocklistRegex !== previousIpRegexAsString && options.ipBlocklistRegex.length === 0) {
    Logger.debug('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else {
    if (options.ipBlocklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlocklistRegex;
      Logger.debug({ ipBlocklistRegex: previousIpRegexAsString }, 'Modifying IP Blocklist Regex');
      ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
    }
  }
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  _setupRegexBlocklists(options);

  Logger.debug(entities);

  entities.forEach((entity) => {
    if (!_isInvalidEntity(entity) && !_isEntityBlocklisted(entity, options)) {
      //do the lookup
      let requestOptions = {
        method: 'GET',
        auth: {
          user: options.apiKey,
          pass: options.privateKey
        },
        json: true
      };

      if (entity.isIPv4) {
        requestOptions.uri = `${options.host}/v0/enrich/ip/${entity.value}`;
        requestOptions.qs = {
          whois: true,
          hostDetails: true,
          linkedAssetCounts: true,
          openPorts: true,
          certificates: true
        };
      } else if (entity.isURL || entity.isDomain) {
        requestOptions.uri = `${options.host}/v0/enrich/host/${entity.value}`;
        requestOptions.qs = {
          whois: true,
          hostDetails: true,
          ipDetails: true,
          linkedAssetCounts: true,
          recentPDNS: true,
          subDomainPDNS: true,
          openPorts: true,
          certificates: true
        };
      } else {
        return;
      }

      Logger.trace({ uri: requestOptions.uri }, 'Request URI');

      tasks.push(function(done) {
        requestWithDefaults(requestOptions, function(error, res, body) {
          if (error) {
            return done(error);
          }

          //Logger.trace({ body: body, statusCode: res ? res.statusCode : 'N/A' }, 'Result of Lookup');

          let result = {};

          if (res.statusCode === 200) {
            // we got data!
            result = {
              entity: entity,
              body: body
            };
          } else if (res.statusCode === 404) {
            // no result found
            result = {
              entity: entity,
              body: null
            };
          } else if (res.statusCode === 202) {
            // no result found
            result = {
              entity: entity,
              body: null
            };
          } else {
            // unexpected status code
            return done({
              err: body,
              detail: `${body.error}: ${body.message}`
            });
          }

          done(null, result);
        });
      });
    }
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (result.body === null || _isMiss(result.body)) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: [],
            details: result.body
          }
        });
      }
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
}

function _isInvalidEntity(entity) {
  // Domains should not be over 100 characters long so if we get any of those we don't look them up
  if (entity.value.length > MAX_ENTITY_LENGTH) {
    return true;
  }

  // Domain labels (the parts in between the periods, must be 63 characters or less
  if (entity.isDomain) {
    const invalidLabel = entity.value.split('.').find((label) => {
      return label.length > MAX_DOMAIN_LABEL_LENGTH;
    });

    if (typeof invalidLabel !== 'undefined') {
      return true;
    }
  }

  if (entity.isIPv4 && IGNORED_IPS.has(entity.value)) {
    return true;
  }

  return false;
}

function _isEntityBlocklisted(entity, options) {
  const blocklist = options.blocklist;

  Logger.trace({ blocklist: blocklist }, 'checking to see what blocklist looks like');

  if (_.includes(blocklist, entity.value.toLowerCase())) {
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'Blocked BlockListed IP Lookup');
        return true;
      }
    }
  }

  if (entity.isDomain) {
    if (domainBlocklistRegex !== null) {
      if (domainBlocklistRegex.test(entity.value)) {
        Logger.debug({ domain: entity.value }, 'Blocked BlockListed Domain Lookup');
        return true;
      }
    }
  }

  return false;
}

function _isMiss(body) {
  if (!body) {
    return true;
  }

  if (
    (Array.isArray(body.whois) && body.whois.length > 0) ||
    (Array.isArray(body.recentPDNS) && body.recentPDNS.length > 0) ||
    (Array.isArray(body.subDomainPDNS) && body.subDomainPDNS.length > 0) ||
    (Array.isArray(body.linkedAssetCounts) && body.linkedAssetCounts.length > 0) ||
    (Array.isArray(body.certificates) && body.certificates.length > 0)
  ) {
    return false;
  }

  return true;
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a RiskIQ API key'
    });
  }
  if (
    typeof userOptions.privateKey.value !== 'string' ||
    (typeof userOptions.privateKey.value === 'string' && userOptions.privateKey.value.length === 0)
  ) {
    errors.push({
      key: 'privateKey',
      message: 'You must provide a RiskIQ Private key'
    });
  }
  cb(null, errors);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions
};
