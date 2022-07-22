FROM registry.access.redhat.com/ubi8/python-39:latest

USER 0 

# Copy cloud-image-val project
COPY . .

# We need epel for keychain package
RUN dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

# Install basic tools
RUN dnf install -y \
    wget \
    unzip \
    keychain

# Install terraform
RUN wget --quiet https://releases.hashicorp.com/terraform/1.2.4/terraform_1.2.4_linux_amd64.zip \
  && unzip terraform_1.2.4_linux_amd64.zip \
  && mv terraform /usr/bin \
  && rm terraform_1.2.4_linux_amd64.zip

# Install python requirements
RUN pip install -r requirements.txt

CMD ["bash"]
