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
		Path mountPoint  = Paths.get("F:\\"); // La unidad virtual

		// Asegurar que el directorio original existe
		if (!Files.exists(localPath)) {
			System.out.println("Error: El directorio original no existe.");
			return;
		}

		MaskValueSet<MountOption> mountOptions = MaskValueSet.of(
			//MountOption.REMOVABLE,           // Permitir eliminar/desmontar
			MountOption.ALT_STREAM,         // Soportar flujos alternativos
			MountOption.NETWORK_DRIVE       // Comportarse como unidad de red
			//MountOption.FILELOCK_USER_MODE   
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
					System.out.println("Archivo procesado: " + file.getFileName());
				} catch (Exception e) {
					System.err.println("Error procesando " + file.getFileName() + ": " + e.getMessage());
				}
			});
			Map<String, ByteArrayOutputStream> updatedMap = new HashMap<>();

			for (Map.Entry<String, ByteArrayOutputStream> entry : decryptedContent.entrySet()) {
				String originalKey = entry.getKey();
				ByteArrayOutputStream value = entry.getValue();

				// Encontrar la posición del último punto
				int lastDotIndex = originalKey.lastIndexOf(".");

				// Remover todo después del último punto
				String newKey = (lastDotIndex != -1) ? originalKey.substring(0, lastDotIndex) : originalKey;

				// Agregar al nuevo mapa con la clave modificada
				updatedMap.put(newKey, value);
			}

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
