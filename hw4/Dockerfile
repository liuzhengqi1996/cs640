# Use an official Python runtime as a parent image
FROM ubuntu:16.04

USER root

# Set the working directory to /app
WORKDIR /

# Copy the current directory contents into the container at /app
# COPY . /assign2
COPY ENTRYPOINT.sh /
COPY fixmininet.sh /
COPY floodlight.patch /
COPY mininet.patch /

# Install any needed packages specified in requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        iproute2 \
        iputils-ping \
        mininet \
        net-tools \
        openvswitch-switch \
        openvswitch-testcontroller \
        tcpdump \
        vim \
        x11-xserver-utils \
        xterm \
        sudo \
        traceroute \
        iputils-arping \
    && apt-get install -y python-pip python-dev python-setuptools flex bison ant openjdk-8-jdk git screen \
    && pip install --upgrade setuptools pip

WORKDIR /
RUN git clone git://github.com/dound/ltprotocol.git \
    && cd ltprotocol \
    && python setup.py install

WORKDIR /
RUN git clone http://github.com/noxrepo/pox \
    && cd pox \
    && git checkout f95dd1

WORKDIR /
RUN git clone https://bitbucket.org/sdnhub/floodlight-plus.git \
    && cd floodlight-plus \
    && patch -p1 < /floodlight.patch

# WORKDIR /
# RUN chmod +x /fixmininet.sh && ./fixmininet.sh


WORKDIR /
RUN chmod +x /ENTRYPOINT.sh \
    && rm -rf /var/lib/apt/lists/*

# WORKDIR /assign2
# RUN ln -s ../pox \
#     && cd /assign2/pox_module \
#     && sudo python setup.py develop \
#     && chmod +x /ENTRYPOINT.sh \
#     && rm -rf /var/lib/apt/lists/*


EXPOSE 8888 6633 6653 6640

ENTRYPOINT ["/ENTRYPOINT.sh"]

# Define environment variable
# ENV NAME World

# Run app.py when the container launches
# CMD ["python", "app.py"]
