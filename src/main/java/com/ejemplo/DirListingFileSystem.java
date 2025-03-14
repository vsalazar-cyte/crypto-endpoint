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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
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

	@Override
	public int zwCreateFile(WString rawPath, DokanIOSecurityContext securityContext, int rawDesiredAccess,
			int rawFileAttributes, int rawShareAccess, int rawCreateDisposition, int rawCreateOptions,
			DokanFileInfo dokanFileInfo) {

		if (dokanFileInfo == null) {
			System.err.println("[ERROR] dokanFileInfo es nulo en zwCreateFile.");
			return NtStatuses.STATUS_INVALID_PARAMETER;
		}
		
		// Obtener el nombre del proceso
		long processId = dokanFileInfo.ProcessId;
		boolean isCopyOp = isCopyOperation(processId);
		if (isCopyOp) {
			System.out.println("Operación de copia detectada en zwCreateFile - Acceso denegado");
			return NtStatuses.STATUS_ACCESS_DENIED;
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
			System.out.println("InvalidPathException: " + rawStr);
		}
		
		/*
		System.out.println("(zwCreateFile) Filename: " + fileName);
		System.out.println("(zwCreateFile) Acceso solicitado: " + rawDesiredAccess);
		System.out.println("(zwCreateFile) Flags de compartición: " + rawShareAccess);
		System.out.println("(zwCreateFile) Disposición de creación: " + rawCreateDisposition);

		//synchronized (decryptedFiles) {
		

		// Modificar la verificación de permisos para ser más permisiva
		
        boolean canRead = (rawDesiredAccess & (WinNT.GENERIC_READ | WinNT.FILE_READ_DATA | WinNT.FILE_READ_EA
                | WinNT.FILE_READ_ATTRIBUTES | WinNT.READ_CONTROL | WinNT.SYNCHRONIZE)) != 0;
        boolean canWrite = (rawDesiredAccess & (WinNT.GENERIC_WRITE | WinNT.FILE_WRITE_DATA | 
                WinNT.FILE_APPEND_DATA | WinNT.GENERIC_ALL | WinNT.FILE_WRITE_ATTRIBUTES | WinNT.FILE_WRITE_EA)) != 0;
		// Logging para debug
		System.out.println("Permisos efectivos - Lectura: " + canRead + ", Escritura: " + canWrite);
		*/
		
		boolean fileExists = decryptedFiles.containsKey(fileName);
		CreateDisposition createDisposition = EnumInteger.enumFromInt(rawCreateDisposition,
				CreateDisposition.values());

		switch (createDisposition) {
		case FILE_SUPERSEDE:
		case FILE_OVERWRITE:
		case FILE_OVERWRITE_IF:
            // Si el archivo existe, limpiar su contenido sin borrar el objeto en memoria
            if (fileExists) {
                System.out.println("(zwCreateFile) Sobrescribiendo archivo (sin eliminar): " + fileName);
                decryptedFiles.get(fileName).reset(); // Limpiar sin borrar
            } else {
                System.out.println("(zwCreateFile) Creando nuevo archivo en sobreescritura: " + fileName);
                decryptedFiles.put(fileName, new ByteArrayOutputStream());
            }
            dokanFileInfo.Context = this.handleHandler.incrementAndGet();
            return NtStatuses.STATUS_SUCCESS;
            
		case FILE_CREATE:
			if (fileExists) {
				return NtStatuses.STATUS_OBJECT_NAME_COLLISION;
			}
			System.out.println("(zwCreateFile) Creando nuevo archivo: " + fileName);
			decryptedFiles.put(fileName, new ByteArrayOutputStream());
			dokanFileInfo.Context = this.handleHandler.incrementAndGet();
			return NtStatuses.STATUS_SUCCESS;

		case FILE_OPEN:
		case FILE_OPEN_IF:
            if (!fileExists) {
                if (createDisposition == CreateDisposition.FILE_OPEN_IF) {
                    System.out.println("(zwCreateFile) Archivo no encontrado, creando nuevo (OPEN_IF): " + fileName);
                    decryptedFiles.put(fileName, new ByteArrayOutputStream());
                } else {
                    System.out.println("(zwCreateFile) Archivo no encontrado: " + fileName);
                    return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
                }
            }
            System.out.println("(zwCreateFile) Abriendo archivo existente: " + fileName);
            dokanFileInfo.Context = this.handleHandler.incrementAndGet();
            return NtStatuses.STATUS_SUCCESS;

		default:
			return NtStatuses.STATUS_INVALID_PARAMETER;
		}
		//}
	}

	@Override
	public int writeFile(WString rawPath, Pointer rawBuffer, int rawBufferLength, IntByReference rawWrittenLength,
			long rawOffset, DokanFileInfo dokanFileInfo) {

		// Obtener el nombre del proceso
		long processId = dokanFileInfo.ProcessId;
		boolean isCopyOp = isCopyOperation(processId);
		if (isCopyOp) {
			System.out.println("Operación de copia detectada en zwCreateFile - Acceso denegado");
			return NtStatuses.STATUS_ACCESS_DENIED;
		}

		String rawStr = rawPath.toString();
		String fileName;
		if (rawStr.equals("\\") || rawStr.isEmpty()) {
			fileName = "";
		} else {
			Path p = Paths.get(rawStr);
			fileName = (p.getFileName() != null ? p.getFileName().toString() : "");
		}

		System.out.println("(writeFile) Escribiendo en: " + fileName + " Offset: " + rawOffset);

		//synchronized (decryptedFiles) {
			ByteArrayOutputStream memoryStream = decryptedFiles.get(fileName);

			// Si no existe, se crea nuevo stream automáticamente (para casos de creación)
			if (memoryStream == null) {
				memoryStream = new ByteArrayOutputStream();
				decryptedFiles.put(fileName, memoryStream);
			}
			
			/*

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
			*/
	            byte[] buffer = new byte[rawBufferLength];
	            rawBuffer.read(0, buffer, 0, rawBufferLength);

	            // **Solución: Escribir datos en la posición correcta en el buffer**
	            memoryStream.write(buffer, (int) rawOffset, rawBufferLength);

	            rawWrittenLength.setValue(rawBufferLength);
	            System.out.println("(writeFile) Datos escritos correctamente.");
	            return NtStatuses.STATUS_SUCCESS;
		//}
	}

	@Override
	public int readFile(WString rawPath, Pointer rawBuffer, int rawBufferLength, IntByReference rawReadLength,
			long rawOffset, DokanFileInfo dokanFileInfo) {

		// Obtener el nombre del proceso
		long processId = dokanFileInfo.ProcessId;
		boolean isCopyOp = isCopyOperation(processId);
		if (isCopyOp) {
			System.out.println("Operación de copia detectada en zwCreateFile - Acceso denegado");
			return NtStatuses.STATUS_ACCESS_DENIED;
		}

		String rawStr = rawPath.toString();
		String fileName;
		if (rawStr.equals("\\") || rawStr.isEmpty()) {
			fileName = "";
		} else {
			Path p = Paths.get(rawStr);
			fileName = (p.getFileName() != null ? p.getFileName().toString() : "");
		}

		// System.out.println("(readfile) Filename: " + fileName);

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

	private boolean isCopyOperation(long processId) {
		try {
			String processName = getProcessName(processId);

			// Verificar procesos conocidos de copia
			Set<String> copyProcesses = new HashSet<>(
					Arrays.asList("cmd.exe", "powershell.exe", "totalcmd.exe", "fastcopy.exe", "teracopy.exe"));

			if (copyProcesses.contains(processName.toLowerCase())) {

				// Para Explorer, verificar operaciones específicas
				if (processName.equalsIgnoreCase("explorer.exe")) {
					return isExplorerCopyOperation(processId);
				}

				// Verificar la línea de comandos del proceso
				String cmdLineQuery = "powershell -Command \"Get-WmiObject Win32_Process -Filter 'ProcessId="
						+ processId + "' | Select-Object -ExpandProperty CommandLine\"";
				Process process = Runtime.getRuntime().exec(cmdLineQuery);
				Scanner s = new Scanner(process.getInputStream()).useDelimiter("\\A");
				String cmdLine = s.hasNext() ? s.next().toLowerCase() : "";

				// Detectar comandos de copia
				if (cmdLine.contains("xcopy") || cmdLine.contains("robocopy") || cmdLine.contains("copy")
						|| cmdLine.contains("move") || cmdLine.contains("cut")) {
					return true;
				}
			}

			// Verificar si el proceso padre es una operación de copia
			String parentPidQuery = "powershell -Command \"Get-WmiObject Win32_Process -Filter 'ProcessId=" + processId
					+ "' | Select-Object -ExpandProperty ParentProcessId\"";
			Process parentProcess = Runtime.getRuntime().exec(parentPidQuery);
			Scanner ps = new Scanner(parentProcess.getInputStream()).useDelimiter("\\A");
			if (ps.hasNext()) {
				long parentPid = Long.parseLong(ps.next().trim());
				return isCopyOperation(parentPid);
			}

			return false;

		} catch (Exception e) {
			System.err.println("Error verificando operación de copia: " + e.getMessage());
			return false;
		}
	}

	private boolean isExplorerCopyOperation(long processId) {
		try {
			// Verificar ventanas y diálogos de Explorer
			String windowQuery = "powershell -Command \"" + "Add-Type -AssemblyName UIAutomationClient; "
					+ "$automation = [System.Windows.Automation.AutomationElement]::RootElement; "
					+ "$windows = $automation.FindAll([System.Windows.Automation.TreeScope]::Children, "
					+ "(New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, "
					+ processId + "))); " + "$windows | ForEach-Object { $_.Current.Name } | Out-String\"";

			Process process = Runtime.getRuntime().exec(windowQuery);
			Scanner s = new Scanner(process.getInputStream()).useDelimiter("\\A");
			String windowInfo = s.hasNext() ? s.next().toLowerCase() : "";

			// Palabras clave que indican operaciones de copia
			Set<String> copyKeywords = new HashSet<>(Arrays.asList("copiar", "copy", "mover", "move", "cortar", "cut",
					"pegar", "paste", "enviar a", "send to", "guardar como", "save as"));

			for (String keyword : copyKeywords) {
				if (windowInfo.contains(keyword)) {
					return true;
				}
			}

			// Verificar operaciones de arrastrar y soltar
			String dragDropQuery = "powershell -Command \"" + "$shell = New-Object -ComObject Shell.Application; "
					+ "$shell.Windows() | ForEach-Object { $_.LocationURL } | Out-String\"";

			process = Runtime.getRuntime().exec(dragDropQuery);
			s = new Scanner(process.getInputStream()).useDelimiter("\\A");
			String locationInfo = s.hasNext() ? s.next().toLowerCase() : "";

			// Si detectamos múltiples ubicaciones abiertas, podría ser una operación de
			// arrastrar y soltar
			return locationInfo.split("\n").length > 1;

		} catch (Exception e) {
			System.err.println("Error verificando ventana de Explorer: " + e.getMessage());
			return false;
		}
	}

	private String getProcessName(long processId) {
		try {
			String processQuery = "powershell -Command \"Get-Process -Id " + processId
					+ " | Select-Object -ExpandProperty ProcessName\"";
			Process process = Runtime.getRuntime().exec(processQuery);
			java.util.Scanner s = new java.util.Scanner(process.getInputStream()).useDelimiter("\\A");
			String processName = s.hasNext() ? s.next().trim() + ".exe" : "unknown.exe";
			return processName.toLowerCase();
		} catch (Exception e) {
			System.err.println("Error getting process name: " + e.getMessage());
			return "unknown.exe";
		}
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
	    //synchronized (decryptedFiles) {
	        String fileName = Paths.get(rawPath.toString()).getFileName().toString();

	        // Si el archivo es temporal, no hacer flush, solo permitir escritura
	        if (fileName.endsWith(".tmp") || fileName.startsWith("~$")) {
	            System.out.println("(flushFileBuffers) Ignorando archivo temporal: " + fileName);
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
	            //decryptedFiles.put(fileName, new ByteArrayOutputStream());
	            //decryptedFiles.get(fileName).write(currentData);
	            memoryStream.flush();
	            System.out.println("(flushFileBuffers) Archivo confirmado en memoria: " + fileName);
	            return NtStatuses.STATUS_SUCCESS;

	        } catch (IOException e) {
	            System.err.println("Error al vaciar buffers en memoria para: " + fileName);
	            return NtStatuses.STATUS_IO_DEVICE_ERROR;
	        }
	    //}
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
		System.out.println("Persistiendo cambios antes de cerrar el sistema de archivos...");

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
					System.out.println("Archivo cifrado guardado: " + outputFile.getAbsolutePath());
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
		System.out.println("(SetFileSecurity) Estableciendo permisos en: " + fileName);

		// Aceptamos todos los cambios de permisos sin aplicarlos realmente (Simulación)
		return NtStatuses.STATUS_SUCCESS;
	}
	
	/*
	@Override
	public int getFileSecurity(WString rawPath, int rawSecurityInformation, Pointer rawSecurityDescriptor, 
	                           int rawSecurityDescriptorLength, IntByReference rawSecurityDescriptorLengthNeeded, 
	                           DokanFileInfo dokanFileInfo) {
	    // Extraer el nombre del archivo (para logging)
	    String fileName = rawPath.toString().replace("\\", "").replace("/", "");
	    System.out.println("(getFileSecurity) Solicitando permisos para: " + fileName);

	    Advapi32 advapi32 = Advapi32.INSTANCE;

	    // Crear e inicializar el descriptor de seguridad
	    WinNT.SECURITY_DESCRIPTOR securityDescriptor = new WinNT.SECURITY_DESCRIPTOR();
	    boolean success = advapi32.InitializeSecurityDescriptor(securityDescriptor, WinNT.SECURITY_DESCRIPTOR_REVISION);
	    if (!success) {
	        System.err.println("Error al inicializar el descriptor de seguridad.");
	        return NtStatuses.STATUS_ACCESS_DENIED;
	    }

	    // Establecer un DACL nulo para otorgar acceso total a todos (sin restricciones)
	    success = advapi32.SetSecurityDescriptorDacl(securityDescriptor, true, null, false);
	    if (!success) {
	        System.err.println("Error al asignar un DACL nulo al descriptor de seguridad.");
	        return NtStatuses.STATUS_ACCESS_DENIED;
	    }

	    // Obtener el tamaño requerido para el descriptor de seguridad
	    int sdSize = securityDescriptor.size();
	    rawSecurityDescriptorLengthNeeded.setValue(sdSize);

	    // Si el buffer proporcionado es muy pequeño, se retorna STATUS_BUFFER_TOO_SMALL
	    if (rawSecurityDescriptorLength < sdSize) {
	        return NtStatuses.STATUS_BUFFER_TOO_SMALL;
	    }

	    // Escribir el descriptor de seguridad en el buffer proporcionado
	    securityDescriptor.write(); // Asegura que la estructura se sincronice con la memoria subyacente
	    byte[] sdBytes = securityDescriptor.getPointer().getByteArray(0, sdSize);
	    rawSecurityDescriptor.write(0, sdBytes, 0, sdSize);

	    return NtStatuses.STATUS_SUCCESS;
	}
	*/
	@Override
	public int moveFile(WString existingFileName, WString newFileName, boolean replaceIfExisting, DokanFileInfo dokanFileInfo) {
	    //synchronized (decryptedFiles) {
	        String oldName = Paths.get(existingFileName.toString()).getFileName().toString();
	        String newName = Paths.get(newFileName.toString()).getFileName().toString();

	        if (!decryptedFiles.containsKey(oldName)) {
	            return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
	        }
	        
	       if (replaceIfExisting && decryptedFiles.containsKey(newName)) {
	            decryptedFiles.remove(newName); // Eliminar el archivo destino si ya existe
	        }

	        ByteArrayOutputStream fileData = decryptedFiles.remove(oldName);
	        decryptedFiles.put(newName, fileData);
	        System.out.println("(moveFile) Archivo renombrado: " + oldName + " → " + newName);
	    //}
	    return NtStatuses.STATUS_SUCCESS;
	}

	@Override
	public int deleteFile(WString rawPath, DokanFileInfo dokanFileInfo) {
	    //synchronized (decryptedFiles) {
	        String fileName = Paths.get(rawPath.toString()).getFileName().toString();

	        System.out.println("(deleteFile) Intentando eliminar: " + fileName);

	        // **Verificar si el archivo está en uso antes de eliminarlo**
	        if (isFileInUse(fileName)) {
	            System.err.println("(deleteFile) Archivo en uso, no se puede eliminar: " + fileName);
	            return NtStatuses.STATUS_SHARING_VIOLATION;
	        }

	        // **Si está en decryptedFiles, eliminarlo**
	        if (decryptedFiles.containsKey(fileName)) {
	            decryptedFiles.remove(fileName);
	            System.out.println("(deleteFile) Archivo eliminado de memoria: " + fileName);
	            return NtStatuses.STATUS_SUCCESS;
	        }

	        // **Si el archivo no estaba en decryptedFiles, verificar si fue creado en la unidad virtual**
	        Path filePath = Paths.get("D:\\", fileName); // Ruta en la unidad virtual
	        File file = filePath.toFile();

	        if (file.exists()) {
	            if (file.delete()) {
	                System.out.println("(deleteFile) Archivo eliminado de la unidad virtual: " + fileName);
	                return NtStatuses.STATUS_SUCCESS;
	            } else {
	                System.err.println("(deleteFile) No se pudo eliminar el archivo: " + fileName);
	                return NtStatuses.STATUS_ACCESS_DENIED;
	            }
	        }

	        // **Si el archivo no existe ni en memoria ni en la unidad virtual, devolver error**
	        System.err.println("(deleteFile) Archivo no encontrado: " + fileName);
	        return NtStatuses.STATUS_OBJECT_NAME_NOT_FOUND;
	    //}
	}


}
