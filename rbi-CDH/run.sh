#! /bin/bash

sudo make build 

mkdir -m 755 -p pkg1
mkdir -m 755 -p pkg2

sudo docker run -d --network host --name cdh-build1 rbi-cdh:v1
sudo docker run -d --network host --name cdh-build2 rbi-cdh:v1

sudo docker cp cdh-build1:/usr/local/bin/confidential-data-hub ./pkg1
sudo docker cp cdh-build2:/usr/local/bin/confidential-data-hub ./pkg2

diffoscope ./pkg1/confidential-data-hub ./pkg2/confidential-data-hub --html diff.html

sudo docker stop cdh-build1
sudo docker stop cdh-build2

sudo docker rm cdh-build1
sudo docker rm cdh-build2
