# cs640
Networking HW

## How to use docker-ized mininet VM

Navigate to the assignment folder.

```
cd hw3/

```

If you haven't built the container already, run:

```
docker build -t hw3 .
```

This will take a while.

Now start the docker container:

```
docker-compose up
```

Open a new tab in your terminal. You need to get the docker container id in order to open a terminal in the docker container.

```
docker ps
```

You should see something like:

```
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS                                    NAMES
73fb5929c091        hw3                 "/ENTRYPOINT.sh"    6 minutes ago       Up 6 minutes        6633/tcp, 6640/tcp, 6653/tcp, 8888/tcp   hw3_app_1
```

In this case, `73fb5929c091` is the container id. It will be different for you.

Now you can open up a bash session in the container:

```
docker exec -it <container_id> bash
```

You can open up more terminal tabs and enter the above command to have multiple bash sessions open.
