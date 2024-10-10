# Default value for entrypoint tag name is latest
ARG ENTRYPOINT_TAG_NAME=latest
ARG CONTROL_VERSION
FROM ghcr.io/jitsecurity-controls/jit-control-entrypoint-alpine:${ENTRYPOINT_TAG_NAME} AS entrypoint-tag

FROM aquasec/trivy:$CONTROL_VERSION

ARG COMMIT_SHA
# Add the label with the commit  SHA
LABEL commit_sha=${COMMIT_SHA}

ENV CONTROL_NAME=trivy

RUN apk update && \
    apk add --no-cache curl git jq && \
    apk upgrade --no-cache libssl3 libcrypto3

COPY --from=entrypoint-tag /entrypoint /opt/entrypoint
COPY pipeline.yml /opt/pipeline.yml
COPY metadata.yml /opt/metadata.yml
COPY ./config/ /opt/

WORKDIR /recipes
COPY ./recipes /recipes

RUN git config --global --add safe.directory /code
USER root
WORKDIR /code

ENV SECURITY_CONTROL_OUTPUT_FILE=/code/results.json

# Fallback to fetching mirrored Trivy Vulnerability DB from ECR to prevent rate limiting
ENV TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db,public.ecr.aws/aquasecurity/trivy-db
ENV TRIVY_JAVA_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-java-db,public.ecr.aws/aquasecurity/trivy-java-db

ENTRYPOINT ["/opt/entrypoint", "trivy"]
