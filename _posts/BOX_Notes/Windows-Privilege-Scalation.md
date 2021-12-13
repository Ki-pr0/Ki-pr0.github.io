
# Vectores de escalada de privilegios en Windows

A continuación se enumeran algunos vectores comunes que podrían permitir a cualquier usuario aumentar sus niveles de privilegio en un sistema Windows.

  -  Credenciales almacenadas: Las credenciales importantes pueden ser guardadas en archivos por el usuario o en el archivo de configuración de una aplicación instalada en el sistema de destino.

  - Explotación del Kernel de Windows: El sistema operativo Windows instalado en el sistema de destino puede tener una vulnerabilidad conocida que puede ser explotada para aumentar los niveles de privilegio.

  -  Permisos inseguros de archivos/carpetas: En algunas situaciones, incluso un usuario con pocos privilegios puede tener privilegios de lectura o escritura sobre archivos y carpetas que pueden contener información sensible.

  - Permisos de servicio inseguros: De forma similar a los permisos sobre archivos y carpetas sensibles, los usuarios con pocos privilegios pueden tener derechos sobre los servicios. Estos pueden ser algo inofensivos, como la consulta del estado del servicio (SERVICE_QUERY_STATUS) o derechos más interesantes, como el inicio y la detención de un servicio (SERVICE_START y SERVICE_STOP, respectivamente).

  -  Secuestro de DLL: Las aplicaciones utilizan archivos DLL para apoyar su ejecución. Puedes pensar en ellos como aplicaciones más pequeñas que pueden ser lanzadas por la aplicación principal. A veces las DLLs que se borran o no están presentes en el sistema son llamadas por la aplicación. Este error no siempre resulta en un fallo de la aplicación, y la aplicación puede seguir ejecutándose. Encontrar una DLL que la aplicación está buscando en una ubicación en la que podemos escribir puede ayudarnos a crear un archivo DLL malicioso que será ejecutado por la aplicación. En este caso, la DLL maliciosa se ejecutará con el nivel de privilegio de la aplicación principal. Si la aplicación tiene un nivel de privilegio superior al de nuestro usuario actual, esto podría permitirnos lanzar un shell con un nivel de privilegio superior.

   - Ruta de servicio no citada: Si la ruta del ejecutable de un servicio contiene un espacio y no está entre comillas, un hacker podría introducir sus propios ejecutables maliciosos para que se ejecuten en lugar del ejecutable previsto.

   - Instalar siempre de forma elevada: Las aplicaciones de Windows pueden instalarse mediante archivos de Windows Installer (también conocidos como paquetes MSI). Estos archivos hacen que el proceso de instalación sea fácil y sencillo. Los sistemas Windows pueden configurarse con la política "AlwaysInstallElevated". Esto permite que el proceso de instalación se ejecute con privilegios de administrador sin necesidad de que el usuario tenga estos privilegios. Esta característica permite a los usuarios instalar software que puede necesitar privilegios más altos sin tener este nivel de privilegio. Si "AlwaysInstallElevated" está configurado, un ejecutable malicioso empaquetado como archivo MSI podría ejecutarse para obtener un nivel de privilegio superior.
    
    Otro software: El software, las aplicaciones o los scripts instalados en la máquina objetivo también pueden proporcionar vectores de escalada de privilegios.
'''
