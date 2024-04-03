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

# Install OpenTofu v1.6.2 which is fully compatible with Terraform v1.5.x
RUN export OPENTOFU_VERSION='1.6.2'

RUN wget --secure-protocol=TLSv1_2 \
    --https-only https://get.opentofu.org/install-opentofu.sh \
    -O install-opentofu.sh

RUN chmod +x install-opentofu.sh; \
    ./install-opentofu.sh --install-method rpm; \
    rm install-opentofu.sh

# Install python requirements
RUN pip install -r requirements.txt

CMD ["bash"]