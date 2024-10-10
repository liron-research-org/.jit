# Base images for the entrypoint, Trivy, and Python
ARG ENTRYPOINT_TAG_NAME=latest
ARG CONTROL_VERSION
FROM ghcr.io/jitsecurity-controls/jit-control-entrypoint-alpine:${ENTRYPOINT_TAG_NAME} AS entrypoint-tag
FROM aquasec/trivy:0.56.1 AS trivy
FROM python:3.10-alpine3.16

ARG COMMIT_SHA
LABEL commit_sha=${COMMIT_SHA}

# Create system group and user
RUN addgroup --system jit && adduser --system jit-user --ingroup jit

# Install necessary tools and upgrade packages
RUN apk update && \
    apk add --no-cache curl git jq openssh openssh-client && \
    apk upgrade -a

# Copy entrypoint, trivy and config files
COPY --from=entrypoint-tag /entrypoint /opt/entrypoint
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY pipeline.yml /opt/pipeline.yml
COPY metadata.yml /opt/metadata.yml
COPY ./config/ /opt/

ENV CONTROL_NAME=trivy
ENV SECURITY_CONTROL_OUTPUT_FILE=/code/results.json
ENV TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db,public.ecr.aws/aquasecurity/trivy-db
ENV TRIVY_JAVA_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-java-db,public.ecr.aws/aquasecurity/trivy-java-db

WORKDIR /code
RUN chown -R jit-user:jit /code && chmod -R 755 /code
USER jit-user:jit
RUN git config --global --add safe.directory /code

ENTRYPOINT ["/opt/entrypoint", "trivy"]
