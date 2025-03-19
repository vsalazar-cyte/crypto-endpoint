package com.ejemplo;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import dev.dokan.dokan_java.DokanFileSystemStub;
import dev.dokan.dokan_java.DokanOperations;
import dev.dokan.dokan_java.DokanUtils;
import dev.dokan.dokan_java.FileSystemInformation;
import dev.dokan.dokan_java.Unsigned;
import dev.dokan.dokan_java.constants.microsoft.CreateDisposition;
import dev.dokan.dokan_java.constants.microsoft.CreateOption;
import dev.dokan.dokan_java.constants.microsoft.NtStatuses;
import dev.dokan.dokan_java.masking.EnumInteger;
import dev.dokan.dokan_java.masking.MaskValueSet;
import dev.dokan.dokan_java.structure.ByHandleFileInformation;
import dev.dokan.dokan_java.structure.DokanFileInfo;
import dev.dokan.dokan_java.structure.DokanIOSecurityContext;
import jnr.ffi.Memory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.DosFileAttributes;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;


/**
 * This filesystem shows the content of a given directory and it sub directories
 */
public class DirListingFileSystem extends DokanFileSystemStub {

	private AtomicLong handleHandler;
	private FileStore fileStore;
	private Path root;
	private Map<String, ByteArrayOutputStream> decryptedFiles;
	private final String mountDrive; // Ejemplo: "D:\\" o "D:"
	private static final ThreadLocal<DokanContext> contextHolder = ThreadLocal.withInitial(DokanContext::new);

	public DirListingFileSystem(Path root, FileSystemInformation fileSystemInformation, String mountDrive) {
		super(fileSystemInformation);
		this.root = root;
		this.handleHandler = new AtomicLong(0);
		FileStore tmp = null;
		try {
			tmp = Files.getFileStore(this.root);
		} catch (IOException e) {
			e.printStackTrace();
		}
		this.fileStore = tmp;
		this.mountDrive = mountDrive;
	}

	public DirListingFileSystem(Path root, FileSystemInformation fileSystemInformation,
			Map<String, ByteArrayOutputStream> decryptedFiles, String mountDrive) {
		super(fileSystemInformation);
		this.root = root;
		this.decryptedFiles = decryptedFiles;
		this.handleHandler = new AtomicLong(0);
		this.mountDrive = mountDrive;
		System.out.println("DirListingFileSystem: " + mountDrive);
	}

	@Override
	public int zwCreateFile(WString rawPath, DokanIOSecurityContext securityContext, int rawDesiredAccess,
			int rawFileAttributes, int rawShareAccess, int rawCreateDisposition, int rawCreateOptions,
			DokanFileInfo dokanFileInfo) {

		if (dokanFileInfo == null) {
			System.err.println("[ERROR] dokanFileInfo es nulo en zwCreateFile.");
			return NtStatuses.STATUS_INVALID_PARAMETER;
		}
		
	    // Verificar que la ruta solicitada pertenezca a la unidad virtual
	    String requestedPath = rawPath.toString();
	    try {
	        Path p = Paths.get(requestedPath);
	        // Si la ruta es absoluta, debe tener la raíz (drive) igual a la unidad virtual
	        if (p.isAbsolute()) {
	            // Por ejemplo, mountDrive podría ser "D:\\" o "D:" (asegúrate de tener el formato consistente)
	            String drive = (p.getRoot() != null ? p.getRoot().toString() : "");
	            if (!drive.equalsIgnoreCase(mountDrive)) {
	                System.err.println("Intento de abrir o crear archivo fuera de la unidad virtual: " + requestedPath);
	                return NtStatuses.STATUS_ACCESS_DENIED;
	            }
	        }
	        // Si la ruta es relativa, se asume que está dentro de la unidad virtual (ya que Dokan la interpreta relativa al mount point)
	    } catch (InvalidPathException e) {
	        System.err.println("Ruta inválida: " + requestedPath);
	        return NtStatuses.STATUS_INVALID_PARAMETER;
	    }

		String rawStr = rawPath.toString();
		String fileName = "";
		try {
			if (rawStr.equals("\\") || rawStr.isEmpty()) {
				fileName = "";
			} else {
				Path p = Paths.get(rawStr);
				fileName = (p.getFileName() != null ? p.getFileName().toString() : "");
			}

			// Manejar directorio raíz
			if (fileName.isEmpty()) {
				dokanFileInfo.IsDirectory = 1;
				dokanFileInfo.Context = 1;
				return NtStatuses.STATUS_SUCCESS;
			}
		} catch (InvalidPathException e) {
			// System.out.println("InvalidPathException: " + rawStr);
		}

		//// System.out.println("(zwCreateFile) Filename: " + fileName);
		// System.out.println("(zwCreateFile) Acceso solicitado: " + rawDesiredAccess);
		// System.out.println("(zwCreateFile) Flags de compartición: " +
		//// rawShareAccess);
		// System.out.println("(zwCreateFile) Disposición de creación: " +
		//// rawCreateDisposition);
		
		synchronized (decryptedFiles) {

			// Modificar la verificación de permisos para ser más permisiva

			boolean canRead = (rawDesiredAccess & (WinNT.GENERIC_READ | WinNT.FILE_READ_DATA | WinNT.FILE_READ_EA
					| WinNT.FILE_READ_ATTRIBUTES | WinNT.READ_CONTROL | WinNT.SYNCHRONIZE)) != 0;
			boolean canWrite = (rawDesiredAccess & (WinNT.GENERIC_WRITE | WinNT.FILE_WRITE_DATA | WinNT.FILE_APPEND_DATA
					| WinNT.GENERIC_ALL | WinNT.FILE_WRITE_ATTRIBUTES | WinNT.FILE_WRITE_EA)) != 0;
			// Logging para debug
			// System.out.println("Permisos efectivos - Lectura: " + canRead + ", Escritura:
			// " + canWrite);

			boolean fileExists = decryptedFiles.containsKey(fileName);
			CreateDisposition createDisposition = EnumInteger.enumFromInt(rawCreateDisposition,
					CreateDisposition.values());

			switch (createDisposition) {
			case FILE_SUPERSEDE:
			case FILE_OVERWRITE:
			case FILE_OVERWRITE_IF:
				// Si el archivo existe, limpiar su contenido sin borrar el objeto en memoria
				if (fileExists) {
					// System.out.println("(zwCreateFile) Sobrescribiendo archivo (sin eliminar): "
					// + fileName);
					decryptedFiles.get(fileName).reset(); // Limpiar sin borrar
				} else {
					// System.out.println("(zwCreateFile) Creando nuevo archivo en sobreescritura: "
					// + fileName);
					decryptedFiles.put(fileName, new ByteArrayOutputStream());
				}
				dokanFileInfo.Context = this.handleHandler.incrementAndGet();
				return NtStatuses.STATUS_SUCCESS;

			case FILE_CREATE:
				if (fileExists) {
					return NtStatuses.STATUS_OBJECT_NAME_COLLISION;
				}
				// System.out.println("(zwCreateFile) Creando nuevo archivo: " + fileName);
				decryptedFiles.put(fileName, new ByteArrayOutputStream());
				dokanFileInfo.Context = this.handleHandler.incrementAndGet();
				return NtStatuses.STATUS_SUCCESS;

			case FILE_OPEN:
			case FILE_OPEN_IF:
				if (!fileExists) {
					if (createDisposition == CreateDisposition.FILE_OPEN_IF) {
						// System.out.println("(zwCreateFile) Archivo no encontrado, creando nuevo
						// (OPEN_IF): " + fileName);
						decryptedFiles.put(fileName, new ByteArrayOutputStream());
					} else {
						// System.out.println("(zwCreateFile) Archivo no encontrado: " + fileName);
						return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
					}
				}
				// System.out.println("(zwCreateFile) Abriendo archivo existente: " + fileName);
				dokanFileInfo.Context = this.handleHandler.incrementAndGet();
				return NtStatuses.STATUS_SUCCESS;

			default:
				return NtStatuses.STATUS_INVALID_PARAMETER;
			}
		}
	}

	@Override
	public int writeFile(WString rawPath, Pointer rawBuffer, int rawBufferLength, IntByReference rawWrittenLength,
			long rawOffset, DokanFileInfo dokanFileInfo) {

		String rawStr = rawPath.toString();
		String fileName;
		if (rawStr.equals("\\") || rawStr.isEmpty()) {
			fileName = "";
		} else {
			Path p = Paths.get(rawStr);
			fileName = (p.getFileName() != null ? p.getFileName().toString() : "");
		}

		// System.out.println("(writeFile) Escribiendo en: " + fileName + " Offset: " +
		// rawOffset);

		synchronized (decryptedFiles) {
			ByteArrayOutputStream memoryStream = decryptedFiles.get(fileName);

			// Si no existe, se crea nuevo stream automáticamente (para casos de creación)
			if (memoryStream == null) {
				memoryStream = new ByteArrayOutputStream();
				decryptedFiles.put(fileName, memoryStream);
			}
			// Obtener contenido actual del archivo
			byte[] data = memoryStream.toByteArray();

			// Ajustar tamaño si es necesario
			int endOffset = (int) rawOffset + rawBufferLength;
			if (endOffset > data.length) {
				data = Arrays.copyOf(data, endOffset);
			}

			// Leer datos desde Dokan
			byte[] buffer = new byte[rawBufferLength];
			rawBuffer.read(0, buffer, 0, rawBufferLength);

			// Copiar datos en la posición correcta
			System.arraycopy(buffer, 0, data, (int) rawOffset, rawBufferLength);

			// Permitir sobrescritura desde un offset sin resetear todo el contenido
			memoryStream.reset();
			memoryStream.write(data, 0, endOffset);

			rawWrittenLength.setValue(rawBufferLength);
			return NtStatuses.STATUS_SUCCESS;

		}
	}

	@Override
	public int readFile(WString rawPath, Pointer rawBuffer, int rawBufferLength, IntByReference rawReadLength,
	                    long rawOffset, DokanFileInfo dokanFileInfo) {

	    // Actualizar el contexto con el PID del proceso que invoca la operación
	    getContext().pid.set(dokanFileInfo.ProcessId);

	    // Detectar si se trata de un intento de copia (por ejemplo, extrayendo el archivo fuera de la unidad virtual)
	    if (isCopyAttempt(rawPath.toString())) {
	        System.err.println("Intento de copia detectado para " + rawPath + " - Acceso denegado.");
	        return NtStatuses.STATUS_ACCESS_DENIED;
	    }

	    // Obtener el nombre del archivo a partir de rawPath
	    String rawStr = rawPath.toString();
	    String fileName;
	    if (rawStr.equals("\\") || rawStr.isEmpty()) {
	        fileName = "";
	    } else {
	        Path p = Paths.get(rawStr);
	        fileName = (p.getFileName() != null ? p.getFileName().toString() : "");
	    }

	    // Obtener los datos en memoria para el archivo solicitado
	    ByteArrayOutputStream baos = decryptedFiles.get(fileName);
	    if (baos == null) {
	        return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
	    }
	    byte[] data = baos.toByteArray();

	    // Validar límites de lectura
	    int offset = (int) rawOffset;
	    if (offset >= data.length) {
	        rawReadLength.setValue(0);
	        return NtStatuses.STATUS_END_OF_FILE;
	    }

	    // Calcular la cantidad de bytes a leer y copiarlos al buffer de Dokan
	    int bytesToRead = Math.min(rawBufferLength, data.length - offset);
	    rawBuffer.write(0, data, offset, bytesToRead);
	    rawReadLength.setValue(bytesToRead);

	    return NtStatuses.STATUS_SUCCESS;
	}

	public DokanContext getContext() {
	    return contextHolder.get();
	}
	
	private boolean isCopyAttempt(String path) {
	    try {
	        int pid = (int) getContext().pid.get();
	        String processCmd = getProcessCommandLine(pid).toLowerCase();

	        // Detectar comandos comunes de copia en Windows
	        return processCmd.contains("copy") ||
	               processCmd.contains("xcopy") ||
	               processCmd.contains("robocopy") ||
	               processCmd.contains("explorer");
	    } catch (Exception e) {
	        return false;
	    }
	}

	private String getProcessCommandLine(int pid) throws IOException, InterruptedException {
	    ProcessBuilder pb = new ProcessBuilder("wmic", "process", "where", "ProcessId=" + pid, "get", "CommandLine", "/FORMAT:LIST");
	    pb.redirectErrorStream(true);
	    Process process = pb.start();

	    StringBuilder commandLine = new StringBuilder();
	    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
	        String line;
	        while ((line = reader.readLine()) != null) {
	            if (line.startsWith("CommandLine=")) {
	                commandLine.append(line.substring("CommandLine=".length()).trim());
	            }
	        }
	    }
	    process.waitFor();
	    return commandLine.toString();
	}


	@Override
	public void cleanup(WString rawPath, DokanFileInfo dokanFileInfo) {
		String rawStr = rawPath.toString();
		String fileName;
		if (rawStr.equals("\\") || rawStr.isEmpty()) {
			fileName = "";
		} else {
			Path p = Paths.get(rawStr);
			fileName = (p.getFileName() != null ? p.getFileName().toString() : "");
		}
	}

	@Override
	public void closeFile(WString rawPath, DokanFileInfo dokanFileInfo) {
		String rawStr = rawPath.toString();
		String fileName;
		if (rawStr.equals("\\") || rawStr.isEmpty()) {
			fileName = "";
		} else {
			Path p = Paths.get(rawStr);
			fileName = (p.getFileName() != null ? p.getFileName().toString() : "");
		}
	}

	@Override
	public int getFileInformation(WString rawPath, ByHandleFileInformation fileInfo, DokanFileInfo dokanFileInfo) {
		String rawStr = rawPath.toString();
		String fileName;
		if (rawStr.equals("\\") || rawStr.isEmpty()) {
			fileName = "";
		} else {
			Path p = Paths.get(rawStr);
			fileName = (p.getFileName() != null ? p.getFileName().toString() : "");
		}

		// Manejar directorio raíz
		if (fileName.isEmpty()) {
			fileInfo.dwFileAttributes = WinNT.FILE_ATTRIBUTE_DIRECTORY; // Es un directorio
			fileInfo.ftCreationTime = getCurrentFileTime();
			fileInfo.ftLastAccessTime = getCurrentFileTime();
			fileInfo.ftLastWriteTime = getCurrentFileTime();
			return NtStatuses.STATUS_SUCCESS;
		}

		// Si el archivo existe en memoria, usar su información
		if (decryptedFiles.containsKey(fileName)) {
			ByteArrayOutputStream fileData = decryptedFiles.get(fileName);

			fileInfo.dwFileAttributes = WinNT.FILE_ATTRIBUTE_ARCHIVE | WinNT.FILE_ATTRIBUTE_NORMAL;

			fileInfo.nFileSizeHigh = 0;
			fileInfo.nFileSizeLow = fileData.size(); // Tamaño en bytes
			fileInfo.ftCreationTime = getCurrentFileTime();
			fileInfo.ftLastAccessTime = getCurrentFileTime();
			fileInfo.ftLastWriteTime = getCurrentFileTime();

			// Definir propiedades adicionales para evitar errores de acceso
			fileInfo.nNumberOfLinks = 1; // Se asume que el archivo tiene un solo enlace
			fileInfo.dwVolumeSerialNumber = 0x19831116; // Número de serie ficticio
			fileInfo.nFileIndexHigh = 0;
			fileInfo.nFileIndexLow = (int) (fileName.hashCode() & 0x7FFFFFFF); // ID único basado en el hash del nombre

			return NtStatuses.STATUS_SUCCESS;
		}

		return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
	}

	private WinBase.FILETIME getCurrentFileTime() {
		long currentTimeMillis = System.currentTimeMillis();
		long fileTime = (currentTimeMillis + 11644473600000L) * 10000; // Convertir a FILETIME (100ns ticks)

		WinBase.FILETIME ft = new WinBase.FILETIME();
		ft.dwLowDateTime = (int) fileTime;
		ft.dwHighDateTime = (int) (fileTime >> 32);
		return ft;
	}

	private ByHandleFileInformation getFileInformation(Path p) throws IOException {
		DosFileAttributes attr = Files.readAttributes(p, DosFileAttributes.class);
		long index = 0;
		if (attr.fileKey() != null) {
			index = (long) attr.fileKey();
		}
		@Unsigned
		int fileAttr = 0;
		fileAttr |= attr.isArchive() ? WinNT.FILE_ATTRIBUTE_ARCHIVE : 0;
		fileAttr |= attr.isSystem() ? WinNT.FILE_ATTRIBUTE_SYSTEM : 0;
		fileAttr |= attr.isHidden() ? WinNT.FILE_ATTRIBUTE_HIDDEN : 0;
		fileAttr |= attr.isReadOnly() ? WinNT.FILE_ATTRIBUTE_READONLY : 0;
		fileAttr |= attr.isDirectory() ? WinNT.FILE_ATTRIBUTE_DIRECTORY : 0;
		fileAttr |= attr.isSymbolicLink() ? WinNT.FILE_ATTRIBUTE_REPARSE_POINT : 0;

		if (fileAttr == 0) {
			fileAttr |= WinNT.FILE_ATTRIBUTE_NORMAL;
		}

		return new ByHandleFileInformation(p.getFileName(), fileAttr, attr.creationTime(), attr.lastAccessTime(),
				attr.lastModifiedTime(), this.volumeSerialnumber, attr.size(), index);
	}

	@Override
	public int findFiles(WString rawPath, DokanOperations.FillWin32FindData fillFindData, DokanFileInfo dokanFileInfo) {
		try {
			for (Map.Entry<String, ByteArrayOutputStream> entry : decryptedFiles.entrySet()) {
				String fileName = entry.getKey();
				ByteArrayOutputStream fileData = entry.getValue();

				// Crear la estructura WIN32_FIND_DATA para mostrar los archivos en la unidad
				// virtual
				WinBase.WIN32_FIND_DATA findData = new WinBase.WIN32_FIND_DATA();
				findData.dwFileAttributes = WinNT.FILE_ATTRIBUTE_NORMAL; // Se asume archivo normal
				WString wFileName = new WString(fileName.replace(".cv", "")); // Quitar extensión cifrada

				char[] fileNameChars = wFileName.toString().toCharArray();
				System.arraycopy(fileNameChars, 0, findData.cFileName, 0,
						Math.min(fileNameChars.length, findData.cFileName.length));

				findData.nFileSizeHigh = 0;
				findData.nFileSizeLow = fileData.size();
				findData.ftCreationTime = getCurrentFileTime();
				findData.ftLastAccessTime = getCurrentFileTime();
				findData.ftLastWriteTime = getCurrentFileTime();

				// Llenar la estructura para que Windows pueda listar los archivos en la unidad
				// virtual
				fillFindData.fillWin32FindData(findData, dokanFileInfo);
			}

			return NtStatuses.STATUS_SUCCESS;
		} catch (Exception e) {
			e.printStackTrace();
			return NtStatuses.STATUS_IO_DEVICE_ERROR;
		}
	}

	@Override
	public int getDiskFreeSpace(LongByReference freeBytesAvailable, LongByReference totalNumberOfBytes,
			LongByReference totalNumberOfFreeBytes, DokanFileInfo dokanFileInfo) {
		if (this.fileStore == null) {
			return NtStatuses.STATUS_UNSUCCESSFUL;
		} else {
			try {
				freeBytesAvailable.setValue(fileStore.getUsableSpace());
				totalNumberOfBytes.setValue(fileStore.getTotalSpace());
				totalNumberOfFreeBytes.setValue(fileStore.getUnallocatedSpace());
				return NtStatuses.STATUS_SUCCESS;
			} catch (IOException e) {
				return NtStatuses.STATUS_IO_DEVICE_ERROR;
			}
		}
	}

	@Override
	public int getVolumeInformation(Pointer rawVolumeNameBuffer, int rawVolumeNameSize,
			IntByReference rawVolumeSerialNumber, IntByReference rawMaximumComponentLength,
			IntByReference rawFileSystemFlags, Pointer rawFileSystemNameBuffer, int rawFileSystemNameSize,
			DokanFileInfo dokanFileInfo) {
		rawVolumeNameBuffer.setWideString(0L, DokanUtils.trimStrToSize(this.volumeName, rawVolumeNameSize));
		rawVolumeSerialNumber.setValue(this.volumeSerialnumber);
		rawMaximumComponentLength.setValue(this.fileSystemInformation.getMaxComponentLength());
		rawFileSystemFlags.setValue(this.fileSystemInformation.getFileSystemFeatures().intValue());
		rawFileSystemNameBuffer.setWideString(0L,
				DokanUtils.trimStrToSize(this.fileSystemInformation.getFileSystemName(), rawFileSystemNameSize));
		return NtStatuses.STATUS_SUCCESS;
	}

	private Path getrootedPath(WString rawPath) {
		String unixPath = rawPath.toString().replace('\\', '/');
		String relativeUnixPath = unixPath;
		if (unixPath.startsWith("/"))
			relativeUnixPath = unixPath.length() == 1 ? "" : unixPath.substring(1); // if it is already the root, we
																					// return the empty string
		return root.resolve(relativeUnixPath);
	}

	@Override
	public int flushFileBuffers(WString rawPath, DokanFileInfo dokanFileInfo) {
		synchronized (decryptedFiles) {
			String fileName = Paths.get(rawPath.toString()).getFileName().toString();

			// Si el archivo es temporal, no hacer flush, solo permitir escritura
			if (fileName.endsWith(".tmp") || fileName.startsWith("~$")) {
				// System.out.println("(flushFileBuffers) Ignorando archivo temporal: " +
				// fileName);
				return NtStatuses.STATUS_SUCCESS;
			}

			if (!decryptedFiles.containsKey(fileName)) {
				System.err.println("(flushFileBuffers) Archivo no encontrado en memoria: " + fileName);
				return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
			}

			// Si el archivo está en uso, retornar error de acceso
			if (isFileInUse(fileName)) {
				System.err.println("(flushFileBuffers) Archivo en uso, no se puede vaciar: " + fileName);
				return NtStatuses.STATUS_SHARING_VIOLATION;
			}

			try {
				ByteArrayOutputStream memoryStream = decryptedFiles.get(fileName);

				// Guardar los cambios en memoria
				byte[] currentData = memoryStream.toByteArray();
				// decryptedFiles.put(fileName, new ByteArrayOutputStream());
				// decryptedFiles.get(fileName).write(currentData);
				memoryStream.flush();
				// System.out.println("(flushFileBuffers) Archivo confirmado en memoria: " +
				// fileName);
				return NtStatuses.STATUS_SUCCESS;

			} catch (IOException e) {
				System.err.println("Error al vaciar buffers en memoria para: " + fileName);
				return NtStatuses.STATUS_IO_DEVICE_ERROR;
			}
		}
	}

	public boolean isFileInUse(String fileName) {
		try {
			Path filePath = Paths.get("D:\\", fileName); // Ajusta según la ruta de tu unidad virtual
			File file = filePath.toFile();

			// Intentar abrir el archivo con acceso exclusivo
			try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
				// Si el archivo se abre sin errores, significa que NO está en uso
				return false;
			}
		} catch (Exception e) {
			// Si hay un error de acceso, el archivo está en uso
			return true;
		}
	}

	@Override
	public void close() {
		// System.out.println("Persistiendo cambios antes de cerrar el sistema de
		// archivos...");

		CryptoVault cryptoVault = new CryptoVault();
		String alias = "AES"; // Ajusta el alias según corresponda

		decryptedFiles.forEach((fileName, stream) -> {
			try {
				// Convertir el contenido en memoria a un InputStream
				byte[] data = stream.toByteArray();
				ByteArrayInputStream bais = new ByteArrayInputStream(data);

				// Definir la ruta de salida para el archivo cifrado: se guarda en el directorio
				// original con extensión .cv
				File outputFile = new File(root.toFile(), fileName + ".cv");
				try (OutputStream fos = new FileOutputStream(outputFile)) {
					// Llamar al método de cifrado basado en streams
					cryptoVault.encryptAEAD(bais, alias, fos);
					// System.out.println("Archivo cifrado guardado: " +
					// outputFile.getAbsolutePath());
				}

				// Opcional: Si deseas borrar la versión en memoria después de cifrarla
				// decryptedFiles.remove(fileName); // O simplemente limpiar al final

			} catch (Exception e) {
				System.err.println("Error al persistir " + fileName + ": " + e.getMessage());
				e.printStackTrace();
			}
		});

		// Vaciar la memoria después de guardar
		decryptedFiles.clear();
	}

	@Override
	public int setFileSecurity(WString rawPath, int rawSecurityInformation, Pointer rawSecurityDescriptor,
			int rawSecurityDescriptorLength, DokanFileInfo dokanFileInfo) {
		// Extraer el nombre del archivo
		String fileName = rawPath.toString().replace("\\", "").replace("/", "");
		// System.out.println("(SetFileSecurity) Estableciendo permisos en: " +
		// fileName);

		// Aceptamos todos los cambios de permisos sin aplicarlos realmente (Simulación)
		return NtStatuses.STATUS_SUCCESS;
	}

	@Override
	public int moveFile(WString existingFileName, WString newFileName, boolean replaceIfExisting,
	                    DokanFileInfo dokanFileInfo) {
	    synchronized (decryptedFiles) {
	        String oldName = Paths.get(existingFileName.toString()).getFileName().toString();
	        String newName = Paths.get(newFileName.toString()).getFileName().toString();

	        // Obtener la letra de la unidad desde la ruta de los archivos
	        String oldDrive = Paths.get(existingFileName.toString()).getRoot().toString();
	        String newDrive = Paths.get(newFileName.toString()).getRoot().toString();

	        // Si la unidad destino es diferente, bloquear el movimiento fuera de la unidad virtual
	        if (!oldDrive.equalsIgnoreCase(newDrive)) {
	            System.err.println("(moveFile) Intento de mover el archivo fuera de la unidad virtual bloqueado: " 
	                               + existingFileName + " → " + newFileName);
	            return NtStatuses.STATUS_ACCESS_DENIED;
	        }

	        // Si el archivo no existe en la unidad virtual, retornar error
	        if (!decryptedFiles.containsKey(oldName)) {
	            return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
	        }

	        // Si se permite reemplazar y el archivo ya existe en la nueva ubicación, eliminarlo
	        if (replaceIfExisting && decryptedFiles.containsKey(newName)) {
	            decryptedFiles.remove(newName);
	        }

	        // Mover dentro de la unidad virtual (renombrar el archivo)
	        ByteArrayOutputStream fileData = decryptedFiles.remove(oldName);
	        decryptedFiles.put(newName, fileData);
	        System.out.println("(moveFile) Archivo renombrado dentro de la unidad virtual: " 
	                           + oldName + " → " + newName);
	    }
	    return NtStatuses.STATUS_SUCCESS;
	}

	@Override
	public int deleteFile(WString rawPath, DokanFileInfo dokanFileInfo) {
		synchronized (decryptedFiles) {
			// Se asume que rawPath viene en formato "\archivo.ext"
			String fileName = Paths.get(rawPath.toString()).getFileName().toString();

			// Verificar si el archivo está en uso antes de eliminarlo
			if (isFileInUse(fileName)) {
				System.err.println("(deleteFile) Archivo en uso, no se puede eliminar: " + fileName);
				return NtStatuses.STATUS_SHARING_VIOLATION;
			}

			// Si está en decryptedFiles, eliminarlo
			if (decryptedFiles.containsKey(fileName)) {
				decryptedFiles.remove(fileName);
				return NtStatuses.STATUS_SUCCESS;
			}

			// Si el archivo no estaba en decryptedFiles, verificar si fue creado en la
			// unidad virtual
			// Se utiliza la letra de la unidad almacenada en mountDrive
			Path filePath = Paths.get(mountDrive, fileName);
			System.out.println("FILE PATH: " + filePath.toString());
			File file = filePath.toFile();

			if (file.exists()) {
				System.out.println("Archivo creado en la unidad virtual");
				if (file.delete()) {
					return NtStatuses.STATUS_SUCCESS;
				} else {
					System.err.println("(deleteFile) No se pudo eliminar el archivo: " + fileName);
					return NtStatuses.STATUS_ACCESS_DENIED;
				}
			}

			System.err.println("(deleteFile) Archivo no encontrado: " + fileName);
			return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
		}
	}

}
