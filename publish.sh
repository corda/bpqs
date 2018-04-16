./gradlew jar
mvn install:install-file -Dfile=./build/libs/corda-pq-signature-1.0-SNAPSHOT.jar -DgroupId=net.corda.research.pq -DartifactId=corda-pq-signature -Dversion=1.0
