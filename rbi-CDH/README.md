# Reproducible Build Confidential-data-hub



## Files



- `run.sh` main script. Use `./run.sh` to run.
- `Makefile` script to make build docker image.
- `Dockerfile` to build docker.



## Instructions

First, run the script to start.

```shell
sudo sh run.sh
```

if  build process is successful, the binary CDH file ` confidential-data-hub` is in `./pkg1`, then bash `./pkg1/confidential-data-hub` to run it.