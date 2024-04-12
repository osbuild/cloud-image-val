#!/bin/bash

for pub_key_file in schutzbot/team_ssh_keys/*.pub; do
  cat "$pub_key_file" | tee -a ~/.ssh/authorized_keys > /dev/null
done
