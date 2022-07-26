FROM python:3.8-slim-buster

# Copy cloud-image-val project
COPY . .

# Install basic tools
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    keychain

# Install aws cli
RUN wget --help
RUN wget https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -O awscliv2.zip
RUN unzip awscliv2.zip
RUN ./aws/install

# Install terraform
RUN wget --quiet https://releases.hashicorp.com/terraform/1.2.4/terraform_1.2.4_linux_amd64.zip \
  && unzip terraform_1.2.4_linux_amd64.zip \
  && mv terraform /usr/bin \
  && rm terraform_1.2.4_linux_amd64.zip

# Install python requirements
RUN pip install -r requirements.txt

CMD ["bash"]
