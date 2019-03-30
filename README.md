SDLC:
* Необходимо смержить изменения в бранч build \ 
  при это запустится сборки которая соберет образ в registry \
   gitlab.tektorg.ru:5001/m1ke/certtools:latest \
* После сборки образа можно cделaть docker-compose pull &&  docker-compose up -d \
  на хостах где используется certbot. \
> НЕОБХОДИМО ПРОВЕРИТЬ ПУТЬ ДО REGISTRY В docker-compose.yml на хостах
> так как я поменял хранилище при переносе сборок из ansible в gitlab

