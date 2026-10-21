FROM wazuh/wazuh-manager:4.14.5
# This lab has no indexer. Remove both Filebeat supervisor and its initializer.
RUN rm -rf /etc/services.d/filebeat && find /etc/cont-init.d -iname '*filebeat*' -delete
COPY wazuh_integration /opt/soc-ai/wazuh_integration
COPY docker/wazuh/custom-soc-ai /var/ossec/integrations/custom-soc-ai
COPY docker/wazuh/healthcheck.py /opt/healthcheck.py
COPY docker/wazuh/zeek-notice-rules.xml /opt/soc-ai/zeek-notice-rules.xml
COPY docker/wazuh/0-local-prepare /etc/cont-init.d/0-local-prepare
COPY docker/wazuh/1-soc-lab /etc/cont-init.d/1-soc-lab
RUN chmod 750 /etc/cont-init.d/0-local-prepare /etc/cont-init.d/1-soc-lab
RUN chown root:wazuh /var/ossec/integrations/custom-soc-ai && chmod 750 /var/ossec/integrations/custom-soc-ai && mkdir -p /spool
