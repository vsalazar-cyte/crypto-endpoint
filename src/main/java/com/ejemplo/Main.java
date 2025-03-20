package com.ejemplo;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.sun.jna.WString;

import dev.dokan.dokan_java.FileSystemInformation;
import dev.dokan.dokan_java.FileSystemInformation;
import dev.dokan.dokan_java.constants.dokany.MountOption;
import dev.dokan.dokan_java.constants.microsoft.FileSystemFlag;
import dev.dokan.dokan_java.masking.MaskValueSet;
import dev.dokan.dokan_java.structure.DokanFileInfo;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {

	public static void main(String[] args) {
		System.out.println("Iniciando el sistema de archivos con Dokan.");

		// Modificar
		Path localPath = Paths.get("C:\\Users\\lStel\\OneDrive\\Documentos\\PruebaCifrado"); 
		Path mountPoint  = Paths.get("M:\\"); // La unidad virtual

		// Asegurar que el directorio original existe
		if (!Files.exists(localPath)) {
			System.out.println("Error: El directorio original no existe.");
			return;
		}

		MaskValueSet<MountOption> mountOptions = MaskValueSet.of(
				//MountOption.DEBUG_MODE //Enable output debug message
				//MountOption.STD_ERR_OUTPUT //Enable output debug message to stderr
				MountOption.ALT_STREAM, //Use alternate stream
				//MountOption.WRITE_PROTECTION //Enable mount drive as write-protected
				MountOption.NETWORK_DRIVE //Use network drive - Dokan network provider need to be installed
				//MountOption.REMOVABLE //Use removable drive
				//MountOption.MOUNT_MANAGER //Use mount manager
				//MountOption.CURRENT_SESSION  //Mount the drive on current session only
				//MountOption.FILELOCK_USER_MODE //Enable Lockfile/Unlockfile operations. Otherwise Dokan will take care of it
		);
		
		// Características del sistema de archivos más completas
		MaskValueSet<FileSystemFlag> fsFeatures = MaskValueSet.of(
			FileSystemFlag.CASE_PRESERVED_NAMES         // Preserve case in filenames
			//FileSystemFlag.CASE_SENSITIVE_SEARCH,     // Allow case-sensitive operations
			//FileSystemFlag.SUPPORTS_OBJECT_IDS,       // Required for some applications
			//FileSystemFlag.SUPPORTS_OPEN_BY_FILE_ID,  // Better file handling
			//FileSystemFlag.UNICODE_ON_DISK,          // Full Unicode support
			//FileSystemFlag.PERSISTENT_ACLS             // Support for permissions
			//FileSystemFlag.NAMED_STREAMS,            // Support alternate data streams
			//FileSystemFlag.SUPPORTS_EXTENDED_ATTRIBUTES  // Support extended attributes
		);
		
		// Configuraci�n del sistema de archivos
		FileSystemInformation fsInfo = new FileSystemInformation(fsFeatures);

		try {
			// Inicializar CryptoVault
			CryptoVault cryptoVault = new CryptoVault();

			// Mapa donde se almacenar�n los archivos descifrados en memoria
			Map<String, ByteArrayOutputStream> decryptedContent = new HashMap<>();

			// Cifrar y descifrar cada archivo en el directorio
			Files.walk(localPath).filter(Files::isRegularFile).forEach(file -> {
				try {
					String alias = "AES";
					String fileName = file.getFileName().toString();
					File encryptedFile;

			        // Obtenemos la ruta relativa respecto a localPath, por ejemplo "docs\\prueba.docx"
			        String relativeKey = localPath.relativize(file).toString();
			        
					// Si el archivo no termina en ".cv", cifrarlo y usar el archivo resultante
					if (!fileName.endsWith(".cv")) {
						cryptoVault.encryptAEAD(file.toFile(), alias);
						encryptedFile = new File(file.toString() + ".cv");
					} else {
						// Si ya está cifrado, usarlo directamente
						encryptedFile = file.toFile();
					}

					System.out.println("Procesando: " + encryptedFile.getName());
					cryptoVault.decryptAEAD(encryptedFile, alias, decryptedContent);
					// TO-DO: Modificar decryptAEAD para que acepte el nombre
					// cryptoVault.decryptAEAD(encryptedFile, alias, decryptedContent, relativeKey);
				} catch (Exception e) {
					System.err.println("Error procesando " + file.getFileName() + ": " + e.getMessage());
				}
			});
			Map<String, ByteArrayOutputStream> updatedMap = new HashMap<>();

			Files.walk(localPath)
			    .filter(Files::isRegularFile)
			    .forEach(file -> {
			        // Obtiene la ruta relativa, por ejemplo "docs\prueba.docx" o "tabla.xlsx"
			        String relativeKey = localPath.relativize(file).toString();
			        // Obtiene el nombre del archivo, por ejemplo "prueba.docx"
			        String fileName = file.getFileName().toString();
			        
			        // Remover la extensión solo en el nombre del archivo:
			        int lastDotIndex = fileName.lastIndexOf(".");
			        String baseFileName = (lastDotIndex != -1) ? fileName.substring(0, lastDotIndex) : fileName;
			        
			        // Si el archivo está en una subcarpeta, se conserva la parte de la ruta de carpeta.
			        Path parent = file.getParent();
			        String parentRelative = "";
			        if (parent != null && !parent.equals(localPath)) {
			            parentRelative = localPath.relativize(parent).toString();
			        }
			        
			        // Reconstruir la nueva clave:
			        // Si existe ruta de carpeta se une con File.separator, de lo contrario, es solo el nombre base.
			        String newKey = parentRelative.isEmpty() ? baseFileName : parentRelative + File.separator + baseFileName;
			        
			        // Buscar el contenido descifrado en decryptedContent.
			        // Se busca primero por el nombre simple y, si no se encuentra, por la ruta relativa.
			        ByteArrayOutputStream baos = null;
			        if (decryptedContent.containsKey(fileName)) {
			            baos = decryptedContent.get(fileName);
			        } else if (decryptedContent.containsKey(relativeKey)) {
			            baos = decryptedContent.get(relativeKey);
			        }
			        
			        // Si se encontró el contenido, se inserta en updatedMap con la nueva clave.
			        if (baos != null) {
			            updatedMap.put(newKey, baos);
			        }
			    });

			
			// Crear el sistema de archivos virtual basado en el contenido descifrado
			try (DirListingFileSystem fs = new DirListingFileSystem(localPath, fsInfo, updatedMap, mountPoint.toString())) {
				// Montar el sistema de archivos
				System.out.println("Montando el sistema de archivos en " + mountPoint );
				fs.mount(mountPoint , mountOptions);
				System.out.println("Sistema de archivos montado. Escribe 'exit' para desmontar y salir.");

				// Esperar entrada del usuario para desmontar
				Scanner scanner = new Scanner(System.in);
				while (true) {
					String input = scanner.nextLine().trim().toLowerCase();
					if (input.equals("exit")) {
						System.out.println("Desmontando el sistema de archivos...");
						fs.unmount();
						System.out.println("Sistema de archivos desmontado. Saliendo...");
						break;
					} else {
						System.out.println("Comando no reconocido. Escribe 'exit' para salir.");
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Error: " + e.getMessage());

		}
	}
}
