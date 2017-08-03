#!/usr/bin/env bash
# Custom scripts should not be dependent on any items or data from the main install options.
# Scripts should function properly when executed outside the main script.py
# Any required switches should be included in the install_custom.txt file.
# If the script requires human interaction, it probably will hang. You've been warned.
# Note, the main script won't return output.
# This is a sample bash script to test and demonstrate this feature.

# Install dependencies
apt-get -y install apt-transport-https, openjdk-8-jdk

# Install Repo
wget -qO https://artifacts.elastic.co/GPG-KEY-elasticsearch

apt-key add GPG-KEY-elasticsearch

echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-5.x.list

# Update the cache
sudo apt-get update

#-----------------------------------------------------------------------------------------------------------------------
# Install Elasticsearch

apt-get -y install elasticsearch

# wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.2.0.deb
# dpkg -i elasticsearch-5.2.0.deb

# Configure and start elasticsearch
update-rc.d elasticsearch defaults 95 10
service elasticsearch start

/bin/systemctl daemon-reload
/bin/systemctl enable elasticsearch.service
systemctl start elasticsearch.service

# Insert elasticsearch config commands here

#-----------------------------------------------------------------------------------------------------------------------
# Install X-Pack for Elasticsearch

# Need to find the ES_HOME dir and then run  -> bin/elasticsearch-plugin --batch install x-pack

# Start elasticsearch
# bin/elasticsearch

#-----------------------------------------------------------------------------------------------------------------------
# Install Kibana

apt-get -y install kibana

# wget https://artifacts.elastic.co/downloads/kibana/kibana-5.2.0-amd64.deb
# dpkg -i kibana-5.2.0-amd64.deb

/bin/systemctl daemon-reload
/bin/systemctl enable kibana.service
systemctl start kibana.service

# Insert Kibana config commands here

#-----------------------------------------------------------------------------------------------------------------------
# Install X-Pack for Kibana

# Need to find the ES_HOME dir and then run  -> bin/kibana-plugin --batch install x-pack

# bin/kibana

#-----------------------------------------------------------------------------------------------------------------------
# Install logstash
apt-get -y  install logstash

# wget https://artifacts.elastic.co/downloads/logstash/logstash-5.2.0.tar.gz
# dpkg -i logstash-5.2.0.tar.gz

#-----------------------------------------------------------------------------------------------------------------------
# Install X-Pack for Kibana

# bin/logstash-plugin install x-pack

#-----------------------------------------------------------------------------------------------------------------------
# Install beats
#-----------------------------------------------------------------------------------------------------------------------
# Install Filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-5.2.0-amd64.deb
dpkg -i filebeat-5.2.0-amd64.deb


# Configure commands for Filebeat here

# Start Filebeat
/etc/init.d/filebeat start

#-----------------------------------------------------------------------------------------------------------------------
# Configure and start
#-----------------------------------------------------------------------------------------------------------------------