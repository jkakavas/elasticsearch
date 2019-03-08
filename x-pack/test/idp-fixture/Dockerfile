FROM geerlingguy/docker-ubuntu1604-ansible:latest

ADD . /fixture
# See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=863199
RUN mkdir -p /usr/share/man/man1
#RUN ansible-playbook /fixture/src/main/resources/provision/playbook.yml
