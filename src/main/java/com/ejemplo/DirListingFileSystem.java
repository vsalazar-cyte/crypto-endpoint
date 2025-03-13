package com.ejemplo;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.DosFileAttributes;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
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

	public DirListingFileSystem(Path root, FileSystemInformation fileSystemInformation) {
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
	}

	public DirListingFileSystem(Path root, FileSystemInformation fileSystemInformation,
			Map<String, ByteArrayOutputStream> decryptedFiles) {
		super(fileSystemInformation);
		this.root = root;
		this.decryptedFiles = decryptedFiles;
		this.handleHandler = new AtomicLong(0);
	}

	/**
	 * @Override public int zwCreateFile(WString rawPath, DokanIOSecurityContext
	 *           securityContext, int rawDesiredAccess, int rawFileAttributes, int
	 *           rawShareAccess, int rawCreateDisposition, int rawCreateOptions,
	 *           DokanFileInfo dokanFileInfo) {
	 * 
	 *           String fileName = rawPath.toString().replace("\\", "_"); // Nombre
	 *           en memoria boolean isRoot = rawPath.toString().equals("\\"); //
	 *           Detectar si es la raíz System.out.println("(zwCreateFile) Archivo
	 *           buscado: " + rawPath);
	 * 
	 *           // Manejar apertura del directorio raíz if (isRoot) {
	 *           dokanFileInfo.IsDirectory = 1; return NtStatuses.STATUS_SUCCESS; }
	 *           boolean existsInMemory = decryptedFiles.containsKey(fileName);
	 *           boolean isDirectory = false;
	 * 
	 *           // Si el archivo existe en memoria, permitir abrirlo if
	 *           (existsInMemory) { dokanFileInfo.Context =
	 *           this.handleHandler.incrementAndGet(); return
	 *           NtStatuses.STATUS_SUCCESS; }
	 * 
	 *           // Si no existe en memoria, marcarlo como no encontrado return
	 *           NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND; }
	 **/
	@Override
	public int zwCreateFile(WString rawPath, DokanIOSecurityContext securityContext, int rawDesiredAccess,
			int rawFileAttributes, int rawShareAccess, int rawCreateDisposition, int rawCreateOptions,
			DokanFileInfo dokanFileInfo) {

		if (dokanFileInfo == null) {
			System.err.println("[ERROR] dokanFileInfo es nulo en zwCreateFile.");
			return NtStatuses.STATUS_INVALID_PARAMETER;
		}

		String fileName = rawPath.toString().replace("\\", "").replace("/", "");

		System.out.println("(zwCreateFile) Filename: " + fileName);

		// Manejar el caso de la raíz (cuando rawPath es "\" o vacío)
		if (fileName.isEmpty() || rawPath.toString().equals("\\")) {
			dokanFileInfo.IsDirectory = 1;
			dokanFileInfo.Context = 1;
			return NtStatuses.STATUS_SUCCESS;
		}

		// Obtener todas las llaves
		Set<String> keys = decryptedFiles.keySet();
		for (String key : keys) {
			System.out.println("[decryptedFiles] Llave: " + key);
		}

		boolean fileExists = decryptedFiles.containsKey(fileName);
		// Manejar los distintos casos según el valor de CreateDisposition
		CreateDisposition createDisposition = EnumInteger.enumFromInt(rawCreateDisposition, CreateDisposition.values());

		// Manejar apertura de archivos existentes
		switch (createDisposition) {
		case FILE_SUPERSEDE:
		case FILE_OVERWRITE_IF:
		case FILE_OVERWRITE:
			System.out.println("(zwCreateFile) Sobrescribiendo archivo: " + fileName);
			// Reseteamos el contenido para sobrescribir
			decryptedFiles.put(fileName, new ByteArrayOutputStream());
			dokanFileInfo.Context = this.handleHandler.incrementAndGet();
			return NtStatuses.STATUS_SUCCESS;

		case FILE_CREATE:
			if (fileExists) {
				return NtStatuses.STATUS_OBJECT_NAME_COLLISION;
			}
			break;

		case FILE_OPEN_IF:
			System.out.println("(zwCreateFile) Abriendo archivo (o creándolo si no existe): " + fileName);
			if (!fileExists) {
				decryptedFiles.put(fileName, new ByteArrayOutputStream());
			}
			dokanFileInfo.Context = this.handleHandler.incrementAndGet();
			return NtStatuses.STATUS_SUCCESS;

		case FILE_OPEN:
			if (!fileExists) {
				return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
			}
			dokanFileInfo.Context = this.handleHandler.incrementAndGet();
			return NtStatuses.STATUS_SUCCESS;

		default:
			return NtStatuses.STATUS_UNSUCCESSFUL;
		}

		// Permitir crear nuevos archivos si se solicita escritura
		if ((rawDesiredAccess & WinNT.GENERIC_WRITE) != 0) {
			System.out.println("(zwCreateFile) Creando archivo en memoria: " + fileName);
			decryptedFiles.put(fileName, new ByteArrayOutputStream());
			dokanFileInfo.IsDirectory = 0;
			dokanFileInfo.Context = this.handleHandler.incrementAndGet();
			return NtStatuses.STATUS_SUCCESS;
		}

		return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
	}

	@Override
	public int writeFile(WString rawPath, Pointer rawBuffer, int rawBufferLength, IntByReference rawWrittenLength,
			long rawOffset, DokanFileInfo dokanFileInfo) {

		String fileName = rawPath.toString().replace("\\", "").replace("/", "");

		System.out.println("(writeFile) Escribiendo en: " + fileName + " Offset: " + rawOffset);

		// Validar existencia del archivo en memoria
		if (!decryptedFiles.containsKey(fileName)) {
			return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
		}

		try {
			// Obtener contenido actual del archivo
			ByteArrayOutputStream memoryStream = decryptedFiles.get(fileName);
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

			// Escribir de nuevo en memoria
			memoryStream.reset();
			memoryStream.write(data);

			rawWrittenLength.setValue(rawBufferLength);
			return NtStatuses.STATUS_SUCCESS;

		} catch (IOException e) {
			e.printStackTrace();
			return NtStatuses.STATUS_IO_DEVICE_ERROR;
		}
	}

	@Override
	public int readFile(WString rawPath, Pointer rawBuffer, int rawBufferLength, IntByReference rawReadLength,
			long rawOffset, DokanFileInfo dokanFileInfo) {

		String fileName = rawPath.toString().replace("\\", "").replace("/", "");

		System.out.println("(readfile) Filename: " + fileName);

		// Obtener todas las llaves
		Set<String> keys = decryptedFiles.keySet();

		// Recorrer e imprimir
		for (String key : keys) {
			System.out.println("[decryptedFiles] Llave: " + key);
		}

		// Revisar si existe el archivo en memoria
		if (!decryptedFiles.containsKey(fileName)) {
			return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
		}

		byte[] data = decryptedFiles.get(fileName).toByteArray();

		// Validar límites de lectura
		int offset = (int) rawOffset;
		if (offset >= data.length) {
			rawReadLength.setValue(0);
			return NtStatuses.STATUS_END_OF_FILE;
		}

		// Cantidad de datos a leer
		int bytesToRead = Math.min(rawBufferLength, data.length - offset);

		// Copiar datos al buffer de Dokan
		rawBuffer.write(0, data, offset, bytesToRead);
		rawReadLength.setValue(bytesToRead);

		return NtStatuses.STATUS_SUCCESS;
	}

	@Override
	public void cleanup(WString rawPath, DokanFileInfo dokanFileInfo) {
		String fileName = rawPath.toString().replace("\\", "").replace("/", "");
		System.out.println("(cleanup) Cerrando archivo: " + fileName);
	}

	@Override
	public void closeFile(WString rawPath, DokanFileInfo dokanFileInfo) {
		String fileName = rawPath.toString().replace("\\", "").replace("/", "");
		System.out.println("(closeFile) Cerrando archivo: " + fileName);
	}

	@Override
	public int getFileInformation(WString rawPath, ByHandleFileInformation fileInfo, DokanFileInfo dokanFileInfo) {
		String fileName = rawPath.toString().replace("\\", "_");

		// Manejar directorio raíz
		if (rawPath.toString().equals("\\")) {
			fileInfo.dwFileAttributes = WinNT.FILE_ATTRIBUTE_DIRECTORY;
			fileInfo.nFileSizeHigh = 0;
			fileInfo.nFileSizeLow = 0;
			return NtStatuses.STATUS_SUCCESS;
		}

		// Si el archivo existe en memoria, usar su información
		if (decryptedFiles.containsKey(fileName)) {
			ByteArrayOutputStream fileData = decryptedFiles.get(fileName);

			fileInfo.dwFileAttributes = WinNT.FILE_ATTRIBUTE_NORMAL;
			fileInfo.nFileSizeHigh = 0;
			fileInfo.nFileSizeLow = fileData.size();
			fileInfo.ftCreationTime = getCurrentFileTime();
			fileInfo.ftLastAccessTime = getCurrentFileTime();
			fileInfo.ftLastWriteTime = getCurrentFileTime();

			return NtStatuses.STATUS_SUCCESS;
		}

		// Si el archivo no está en memoria, verificar si existe en el disco cifrado
		Path encryptedFilePath = getEncryptedFilePath(rawPath);
		if (Files.exists(encryptedFilePath)) {
			try {
				// Descifrar el archivo al vuelo y almacenarlo en memoria
				CryptoVault cryptoVault = new CryptoVault();
				Map<String, ByteArrayOutputStream> decryptedContent = new HashMap<>();
				cryptoVault.decryptAEAD(encryptedFilePath.toFile(), "AES", decryptedContent);

				if (!decryptedContent.isEmpty()) {
					ByteArrayOutputStream outputStream = decryptedContent.values().iterator().next();
					decryptedFiles.put(fileName, outputStream);

					fileInfo.dwFileAttributes = WinNT.FILE_ATTRIBUTE_NORMAL;
					fileInfo.nFileSizeHigh = 0;
					fileInfo.nFileSizeLow = outputStream.size();
					fileInfo.ftCreationTime = getCurrentFileTime();
					fileInfo.ftLastAccessTime = getCurrentFileTime();
					fileInfo.ftLastWriteTime = getCurrentFileTime();

					return NtStatuses.STATUS_SUCCESS;
				}
			} catch (Exception e) {
				return NtStatuses.STATUS_ACCESS_DENIED;
			}
		}

		// Si el archivo no existe en memoria ni cifrado en el disco, devolver error
		return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
	}

	// Devuelve la ruta del archivo cifrado en la carpeta real
	private Path getEncryptedFilePath(WString rawPath) {
		return root.resolve(getrootedPath(rawPath) + ".cv");
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
	public int flushFileBuffers(WString fileName, DokanFileInfo info) {
		return 0; // Retorna �xito para evitar errores
	}

	@Override
	public void close() {
		System.out.println("Persistiendo cambios antes de cerrar el sistema de archivos...");

		decryptedFiles.forEach((fileName, stream) -> {
			try {
				byte[] data = stream.toByteArray();
				File decryptedFile = new File(root.toFile(), fileName);

				// 1. Guardar temporalmente el archivo descifrado en disco
				Files.write(decryptedFile.toPath(), data);
				System.out.println("Archivo descifrado guardado temporalmente: " + decryptedFile.getAbsolutePath());

				// 2. Volver a cifrar
				CryptoVault cryptoVault = new CryptoVault();
				cryptoVault.encryptAEAD(decryptedFile, "AES");
				System.out.println("Archivo cifrado nuevamente: " + decryptedFile.getAbsolutePath() + ".cv");

				// 3. Eliminar el archivo temporal en claro
				Files.delete(decryptedFile.toPath());
				System.out.println("Archivo temporal eliminado: " + decryptedFile.getAbsolutePath());

			} catch (Exception e) {
				System.err.println("Error al persistir " + fileName + ": " + e.getMessage());
				e.printStackTrace();
			}
		});

		// Vaciar la memoria después de guardar
		decryptedFiles.clear();
	}

}
