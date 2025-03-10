package com.ejemplo;

import java.nio.file.Paths;
import java.util.Scanner;

import com.sun.jna.WString;

import dev.dokan.dokan_java.FileSystemInformation;
import dev.dokan.dokan_java.FileSystemInformation;
import dev.dokan.dokan_java.constants.dokany.MountOption;
import dev.dokan.dokan_java.constants.microsoft.FileSystemFlag;
import dev.dokan.dokan_java.masking.MaskValueSet;
import dev.dokan.dokan_java.structure.DokanFileInfo;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {
    public static void main(String[] args) {
        System.out.println("Iniciando el sistema de archivos con Dokan.");

        Path directorioReal = Paths.get("C:\\Users\\lStel\\OneDrive\\Documentos\\Prueba");  // Modifica esta ruta a tu carpeta real
        Path puntoMontaje = Paths.get("D:\\");  // La unidad virtual (elige una que no esté en uso)

        // Opciones de montaje
        MaskValueSet<MountOption> mountOptions = MaskValueSet.of(
                MountOption.STD_ERR_OUTPUT,
                MountOption.ALT_STREAM
        );

        // Opciones del sistema de archivos
        MaskValueSet<FileSystemFlag> fsFeatures = MaskValueSet.of(
                FileSystemFlag.CASE_PRESERVED_NAMES,   // Mantener nombres originales
                FileSystemFlag.SUPPORTS_OBJECT_IDS,    // Soporta ID de archivos (necesario para MS Office)
                FileSystemFlag.SUPPORTS_REPARSE_POINTS, // Permite referencias a archivos
                FileSystemFlag.CASE_SENSITIVE_SEARCH // Soporta nombres sensibles a mayúsculas/minúsculas
        );

        // Configuración del sistema de archivos
        FileSystemInformation fsInfo = new FileSystemInformation(fsFeatures);

        try (DirListingFileSystem fs = new DirListingFileSystem(directorioReal, fsInfo)) {
            System.out.println("Montando el sistema de archivos en " + puntoMontaje);
            fs.mount(puntoMontaje, mountOptions);
            System.out.println("Sistema de archivos montado. Escribe 'exit' para desmontar y salir.");

            // Escuchar la entrada del usuario
            Scanner scanner = new Scanner(System.in);
            while (true) {
                String input = scanner.nextLine().trim().toLowerCase();
                if (input.equals("exit")) {
                    System.out.println("Desmontando el sistema de archivos...");
                    fs.cleanup(new WString(""), new DokanFileInfo());  // Llama a cleanup
                    fs.closeFile(new WString(""), new DokanFileInfo());  // Llama a closeFile
                    System.out.println("Sistema de archivos desmontado. Saliendo...");
                    break;
                } else {
                    System.out.println("Comando no reconocido. Escribe 'exit' para salir.");
                }
            }
        }
    }
}
