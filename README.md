# RedTFG

//////////////////////////////////////////////////////////////

Rama int_fase1:

(El historial de commits del desarrollo de esta fase se encuentran disponibles en el repositorio http://github.com/isabelplaza/PruebaINT.git)

Cualquier cambio en la maqueta requiere:

   1. make p4-buid
   2. make app-buid


Para arrancar la maqueta:
  
   1. $ make start-v4
      $ make app-reload
      $ make netcfg
   2. mininet> h1 ping h2 (y viceversa)
   3. $ make app-reload
   4. mininet> h1 arp -i h1-eth0 -s 172.16.1.2 00:00:00:00:00:1B
      mininet> h2 arp -i h2-eth0 -s 172.16.1.1 00:00:00:00:00:1A
      mininet> h1 ping h2



Estas son las instrucciones para tener en el contenedor Docker los ficheros de send.py y receive.py:

   1. Crear una carpera llamada "shared" en el directorio "./util/docker/stratum_bmv2/"
   2. Pegar en dicha carpeta la version definitiva de los ficheros send.py y receive.py. IMPORTANTE!!: Si se hace cualquier modificación, hay que recompilar la imagen de docker de nuevo (paso 4).
   3. Añadir la siguiente línea antes del ultimo COPY en el fichero "./util/docker/stratum_bmv2/Dockerfile"
        ADD ./shared /root
   4. Compilar la imagen de docker:
        cd ./util/docker/
        make build-stratum_bmv2
   5. Arrancar la maqueta en el directorio raíz del repositorio

Una vez arrancada la maqueta, ejecutar los comandos directamente en los hosts de mininet:

    cd <dir_raíz_repositorio>
    util/mn-cmd h2 python receive.py -c h2-eth0 # en un terminal
    util/mn-cmd h1 python send.py -e 00:00:00:00:00:1a,00:00:00:00:00:1b -i 172.16.1.1,172.16.1.2,0 -p 3 -c h1-eth0 # en otro terminal

//////////////////////////////////////////////////////////////


