FROM quay.io/cloudexperience/cloud-image-val-base:latest

# Copy cloud-image-val project
COPY . .

CMD ["bash"]
