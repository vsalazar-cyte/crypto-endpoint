# Instrucciones
1. Instalar dokan en el computador con sistema operativo Windows. Concretamente, versión 1.4.0 disponible en: https://github.com/dokan-dev/dokany/releases?page=2
2. En la carpeta `libs` se encuentra el JAR asociado a dokan-java. 
```
mvn install:install-file -Dfile=libs/dokan-java-1.2.0-SNAPSHOT.jar -DgroupId=dev.dokan -DartifactId=dokan-java -Dversion=1.2.0-SNAPSHOT -Dpackaging=jar
```
En caso de fallo, la librería corresponde al siguiente repositorio: https://github.com/dokan-dev/dokan-java. Sin embargo, sería necesario descargar el proyecto y generar el JAR mediante `gradle`. 

3. Replicar lo anterior, para el jar asociado a H2: 
```
mvn install:install-file -Dfile=h2-2.2.224.jar -DgroupId=com -DartifactId=h2database -Dversion=2.2.224 -Dpackaging=jar
```
4. A nivel de código, en la clase `Main.java` modificar las siguientes variables:
```
		Path localPath = Paths.get("<CARPETA A CIFRAR>"); 
		Path mountPoint  = Paths.get("<UNIDAD VIRTUAL>"); 
```
5. Ejecutar el código y verificar que los archivos en la carpeta original son cifrados con el formato `.cv` (si ya lo estaban, permanecen igual). Abrir la unidad virtual desde el explorador de archivos e interactuar con los elementos disponibles, todos deberían ser accesibles y legibles.
6. Escribir `exit` en la consola y aguardar a que se desmonte la unidad y finalice la ejecución del programa. Todos los archivos en la ruta original deberían ser sobreescritos.


# Consideraciones

* El procesamiento es bastante lento, pese a que funciona. Aún no detecto la razón de ello. 
* Los archivos de la suite de Microsoft Office, así como los PDF y TXT (dependiendo con qué aplicación se inicien, con bloc de notas tradicional el comportamiendo es errático), pueden ser abiertos y modificados.
* Por ahora, no es posible modificar y sobreescribir imágenes u otros elementos binarios de este tipo. De acuerdo con lo investigado, se debe a la forma en que se persisten los cambios y se reemplaza el archivo original.
* Todos los archivos en la ruta original se sobreescriben una vez culmina la ejecución, independiente de si los elementos en la unidad virtual son modificados o no.
* La eliminación de archivos no funciona, pero añadir nuevos sí. 
* Para seguir trabajando con los permisos y moderar las acciones de copia en locaciones externas, pero habilitando cualquier operación de escritura, creación o eliminación se deberían adaptar los métodos `zwCreateFile`, `readFile` y `writeFile`, principalmente. Aunque se han implementado las funciones auxiliares isCopyOperation y isExplorerCopyOperation, todavía no son del todo efectivas. 
