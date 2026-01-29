FROM ubuntu:24.04


ENV user app
ENV chall_port 10001

RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list && \
    apt-get update && apt-get -y install socat

RUN useradd -m $user

WORKDIR /home/$user

COPY vuln /home/$user/vuln
COPY flag /home/$user/flag

RUN chown -R root:$user /home/$user
RUN chmod 755 /home/$user/vuln
RUN chmod 440 /home/$user/flag

USER $user
EXPOSE $chall_port

CMD socat -T 30 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/vuln
