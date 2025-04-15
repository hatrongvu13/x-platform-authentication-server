FROM openjdk:17

LABEL authors="hatrongvu"

WORKDIR /opt/service

COPY /target/*.jar /opt/service/app.jar

COPY /src/main/resources /opt/service/resources_default

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

RUN chgrp -R 0 ./ && chmod -R g=u ./

RUN ls -l /

ENTRYPOINT ["/entrypoint.sh"]