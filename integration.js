"use strict";

let request = require("request");
let _ = require("lodash");
let util = require("util");
let net = require("net");
let config = require("./config/config");
let async = require("async");
let fs = require("fs");
let Logger;

let requestWithDefaults;
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlacklistRegex = null;
let ipBlacklistRegex = null;
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

  if (
    typeof config.request.cert === "string" &&
    config.request.cert.length > 0
  ) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === "string" && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (
    typeof config.request.passphrase === "string" &&
    config.request.passphrase.length > 0
  ) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === "string" && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (
    typeof config.request.proxy === "string" &&
    config.request.proxy.length > 0
  ) {
    defaults.proxy = config.request.proxy;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _setupRegexBlacklists(options) {
  if (
    options.domainBlacklistRegex !== previousDomainRegexAsString &&
    options.domainBlacklistRegex.length === 0
  ) {
    Logger.debug('Removing Domain Blacklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlacklistRegex = null;
  } else {
    if (options.domainBlacklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlacklistRegex;
      Logger.debug(
        { domainBlacklistRegex: previousDomainRegexAsString },
        'Modifying Domain Blacklist Regex'
      );
      domainBlacklistRegex = new RegExp(options.domainBlacklistRegex, 'i');
    }
  }

  if (
    options.ipBlacklistRegex !== previousIpRegexAsString &&
    options.ipBlacklistRegex.length === 0
  ) {
    Logger.debug('Removing IP Blacklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlacklistRegex = null;
  } else {
    if (options.ipBlacklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlacklistRegex;
      Logger.debug({ ipBlacklistRegex: previousIpRegexAsString }, 'Modifying IP Blacklist Regex');
      ipBlacklistRegex = new RegExp(options.ipBlacklistRegex, 'i');
    }
  }
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

   _setupRegexBlacklists(options);

  Logger.debug(entities);

  entities.forEach(entity => {
    if (_isInvalidEntity(entity) || _isEntityBlacklisted(entity, options)) {
        next(null);
      } else if (entity.value){
      //do the lookup
      let requestOptions = {
        method: "GET",
        auth: {
          user: options.apiKey,
          pass: options.privateKey
        },
        json: true
      };

      if (entity.isIPv4 && !IGNORED_IPS.has(entity.value)) {
        requestOptions.uri =
          options.host +
          "/v0/enrich/ip/" +
          entity.value +
          "?whois=true&hostDetails=true&linkedAssetCounts=true&openPorts=true&certificates=true";
      } else if (entity.isURL || entity.isDomain) {
        requestOptions.uri =
          options.host +
          "/v0/enrich/host/" +
          entity.value +
          "?whois=true&hostDetails=true&ipDetails=true&linkedAssetCounts=true&recentPDNS=true&subDomainPDNS=true&openPorts=true&certificates=true";
      } else {
        Logger.error({ entity: entity }, DATA_TYPE_ERROR);
        throw new Error(DATA_TYPE_ERROR);
      }

      Logger.trace({ uri: options }, "Request URI");

      tasks.push(function(done) {
        requestWithDefaults(requestOptions, function(error, res, body) {
          Logger.trace({ body: body, statusCode: res.statusCode }, "Result of Lookup");

          if (error) {
            done(error);
            return;
          }

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
          }
          if (body.error) {
            // entity not found
            result = {
              entity: entity,
              body: null
            };
          }
          done(null, result);
        });
      });
    }
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      cb(err);
      return;
    }

    results.forEach(result => {
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

  return false;
}

function _isEntityBlacklisted(entity, options) {
  const blacklist = options.blacklist;

  Logger.trace({ blacklist: blacklist }, 'checking to see what blacklist looks like');

  if (_.includes(blacklist, entity.value.toLowerCase())) {
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlacklistRegex !== null) {
      if (ipBlacklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'Blocked BlackListed IP Lookup');
        return true;
      }
    }
  }

  if (entity.isDomain) {
    if (domainBlacklistRegex !== null) {
      if (domainBlacklistRegex.test(entity.value)) {
        Logger.debug({ domain: entity.value }, 'Blocked BlackListed Domain Lookup');
        return true;
      }
    }
  }

  return false;
}

function _isMiss(body) {
  if (
    body &&
    Array.isArray(body.whois) &&
    body.whois.length === 0 ||
    Array.isArray(body.recentPDNS) &&
    body.recentPDNS.length === 0 ||
    Array.isArray(body.subDomainPDNS) &&
    body.subDomainPDNS.length === 0 ||
    Array.isArray(body.linkedAssetCounts) &&
    body.linkedAssetCounts.length === 0 ||
    Array.isArray(body.certificates) &&
    body.certificates.length === 0
  ) {
    return true;
  }
  return false;
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== "string" ||
    (typeof userOptions.apiKey.value === "string" &&
      userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: "apiKey",
      message: "You must provide a RiskIQ API key"
    });
  }
  if (
    typeof userOptions.privateKey.value !== "string" ||
    (typeof userOptions.privateKey.value === "string" &&
      userOptions.privateKey.value.length === 0)
  ) {
    errors.push({
      key: "privateKey",
      message: "You must provide a RiskIQ Private key"
    });
  }
  cb(null, errors);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions
};
