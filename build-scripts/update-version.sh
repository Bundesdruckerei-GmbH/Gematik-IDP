#!/bin/bash -e

mvn $MAVEN_CLI_OPTS --file=./pom.xml versions:set -DremoveSnapshot=true
CURRENT_VERSION=$(mvn $MAVEN_CLI_OPTS --file=./pom.xml help:evaluate -Dexpression=project.version -q -DforceStdout)
NEW_VERSION="${CURRENT_VERSION}${VERSION_SUFFIX}"

echo "Updating Version from ${CURRENT_VERSION} to ${NEW_VERSION}"
mvn $MAVEN_CLI_OPTS --file=./pom.xml versions:set -DnewVersion=${NEW_VERSION}
