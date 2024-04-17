FROM registry.access.redhat.com/ubi8/python-39:latest

USER 0

# Copy cloud-image-val project
COPY ./requirements.txt ./

# We need epel for keychain package
RUN dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

# Install basic tools
RUN dnf install -y \
    wget \
    unzip \
    keychain

# Install terraform
RUN tf_version="1.4.6"; \
    if [[ $(uname -m) == "aarch64" ]]; \
    then wget --quiet https://releases.hashicorp.com/terraform/"${tf_version}"/terraform_"${tf_version}"_linux_arm64.zip; \
    else wget --quiet https://releases.hashicorp.com/terraform/"${tf_version}"/terraform_"${tf_version}"_linux_amd64.zip; fi; \
    unzip terraform_"${tf_version}"_linux_*.zip \
    && mv terraform /usr/bin \
    && rm terraform_"${tf_version}"_linux_*.zip

# Install python requirements
RUN pip install -r requirements.txt

CMD ["bash"]