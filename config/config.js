module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'RiskIQ SIS',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'RIQ',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'RiskIQ provides comprehensive discovery, intelligence, and mitigation of threats associated with an organization’s digital presence.',
  entityTypes: ['IPv4', 'url', 'domain'],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/riskiq.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/riq-block.js'
    },
    template: {
      file: './templates/riq-block.hbs'
    }
  },
  summary: {
    component: {
      file: './components/riq-summary.js'
    },
    template: {
      file: './templates/riq-summary.hbs'
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the RiskIQ integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the RiskIQ integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the RiskIQ integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the RiskIQ integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',

    rejectUnauthorized: true
  },
  logging: {
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'host',
      name: 'RiskIQ SIS API URL',
      description: 'The host to use for the RiskIQ SIS API',
      default: 'https://api.riskiq.net',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'apiKey',
      name: 'API Key',
      description: 'RiskIQ Security Intelligence Services API Key',
      default: '',
      type: 'text',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'privateKey',
      name: 'Private Key',
      description: 'RiskIQ Security Intelligence Services Private Key',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'blocklist',
      name: 'Ignore List',
      description: 'List of domains and IPs that you never want to send to RiskIQ',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'domainBlocklistRegex',
      name: 'Ignore Domain Regex',
      description:
        'Domains that match the given regex will not be looked up.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'ipBlocklistRegex',
      name: 'Ignore IP Regex',
      description: 'IPs that match the given regex will not be looked up.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    }
  ]
};
