export const moduleIndexPatterns = (eventsIndex) => ({
  vulnerabilities: 'wazuh-states-vulnerabilities-*',
  sca: 'wazuh-states-sca-*',
  fim: 'wazuh-alerts-*',
  rootcheck: 'wazuh-states-rootcheck-*',
  malware: 'wazuh-alerts-*',
  rules: eventsIndex,
  decoders: eventsIndex,
  authentication: eventsIndex,
  mitre: eventsIndex,
  compliance: eventsIndex,
  threatIntelligence: 'wazuh-alerts-*',
  assets: 'wazuh-states-inventory-*',
});
